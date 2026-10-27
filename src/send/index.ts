import { createTransport } from "nodemailer";
import { describeChannel } from "../compose.ts";
import type { Config } from "../config.ts";
import { appendHistory, readHistory, recentlySent, type HistoryEntry } from "../history.ts";
import type { Channel, Evidence, Report } from "../types.ts";
import { cloudflarePhishing, netcraftMail, netcraftUrls } from "./apis.ts";

export type SendStatus = "sent" | "manual" | "skipped" | "failed";

export interface SendResult {
  report: Report;
  status: SendStatus;
  detail: string;
}

export interface SendOptions {
  config: Config;
  evidence: Evidence;
  /** Send again even if the same URL went to the same place in the last few days. */
  force?: boolean;
  /** Called for each report that needs a person: web forms, or e-mail without SMTP. */
  onManual?: (report: Report) => Promise<void>;
}

/** The one channel to use per destination, so the same abuse desk never gets the report twice. */
export function chooseChannel(channels: Channel[], config: Config): Channel | undefined {
  const usable = (c: Channel) =>
    c.kind === "api" ? c.api === "netcraft" || !!(config.cloudflareToken && config.cloudflareAccountId) : c.kind === "email" && !!config.smtpUrl;
  return channels.find((c) => c.kind === "api" && usable(c))
    ?? channels.find((c) => c.kind === "email" && usable(c))
    ?? channels.find((c) => c.kind === "form")
    ?? channels.find((c) => c.kind === "email");
}

/**
 * Deliver reports that can be delivered automatically (APIs, SMTP) and hand the rest to `onManual`.
 * Every automatic delivery is written to ~/.scamdown/history.json.
 */
export async function sendReports(all: Report[], opts: SendOptions): Promise<SendResult[]> {
  const { config, evidence } = opts;
  const reports = all.filter((r) => r.channel === chooseChannel(r.target.channels, config));
  if (!config.name || !config.email) throw new Error("Set your name and e-mail first (scamdown init). Abuse desks need someone to reply to.");
  const reporter = { name: config.name, email: config.email };
  const history = await readHistory();
  const results: SendResult[] = [];
  const log: HistoryEntry[] = [];
  const mailer = config.smtpUrl ? createTransport(config.smtpUrl) : null;
  let mailSentToNetcraft = false;

  for (const report of reports) {
    const { channel, target } = report;
    const channelId = describeChannel(channel);
    const fresh = report.urls.filter((u) => opts.force || !recentlySent(history, u, target.id, channelId));
    if (!fresh.length) {
      results.push({ report, status: "skipped", detail: "already reported here in the last few days" });
      continue;
    }

    try {
      let detail: string;
      if (channel.kind === "api" && channel.api === "netcraft") {
        detail = await netcraftUrls(reporter.email, fresh, report.body);
        if (evidence.rawEmail && !mailSentToNetcraft) {
          detail += `; e-mail: ${await netcraftMail(reporter.email, evidence.rawEmail)}`;
          mailSentToNetcraft = true;
        }
      } else if (channel.kind === "api" && channel.api === "cloudflare") {
        if (!config.cloudflareToken || !config.cloudflareAccountId) {
          results.push({ report, status: "skipped", detail: "no Cloudflare API token; use the web form instead" });
          continue;
        }
        const ids = await cloudflarePhishing({
          token: config.cloudflareToken,
          accountId: config.cloudflareAccountId,
          ...reporter,
          urls: fresh,
          justification: report.body,
        });
        detail = `Cloudflare report ${ids.join(", ")}`;
      } else if (channel.kind === "email" && mailer) {
        const info = await mailer.sendMail({
          from: config.smtpFrom ?? `${reporter.name} <${reporter.email}>`,
          replyTo: reporter.email,
          to: channel.to,
          subject: report.subject,
          text: report.body,
          attachments: [
            ...(evidence.screenshot
              ? [{ filename: evidence.screenshot.filename, content: Buffer.from(evidence.screenshot.data), contentType: evidence.screenshot.mime }]
              : []),
            ...(evidence.rawEmail ? [{ filename: "phishing-email.eml", content: evidence.rawEmail, contentType: "message/rfc822" }] : []),
          ],
        });
        detail = `mail ${info.messageId ?? "sent"}`;
      } else {
        await opts.onManual?.(report);
        results.push({ report, status: "manual", detail: channelId });
        continue;
      }
      results.push({ report, status: "sent", detail });
      for (const url of fresh) log.push({ url, target: target.id, channel: channelId, at: new Date().toISOString(), ok: true, detail });
    } catch (e) {
      const detail = (e as Error).message;
      results.push({ report, status: "failed", detail });
      for (const url of fresh) log.push({ url, target: target.id, channel: channelId, at: new Date().toISOString(), ok: false, detail });
    }
  }
  await appendHistory(log);
  return results;
}
