import { analyzeUrl, planTargets } from "./analyze.ts";
import { composeReports } from "./compose.ts";
import type { Config } from "./config.ts";
import { extractFromText, normalizeUrl } from "./extract.ts";
import { lookupIp } from "./net/rdap.ts";
import { MAIL_PROVIDERS } from "./providers.ts";
import { urlscan } from "./send/apis.ts";
import type { Evidence, Extracted, Report, ScreenshotFile, Target, UrlAnalysis } from "./types.ts";

export const MAX_URLS = 20;

export interface Input {
  /** Anything pasted: a link, an SMS, a chat message, an e-mail body. */
  text?: string;
  urls?: string[];
  screenshot?: ScreenshotFile;
  /** Raw .eml source of a phishing e-mail. */
  rawEmail?: string;
}

export interface Collected {
  urls: string[];
  extracted: Extracted;
  evidence: Partial<Evidence>;
  emailTargets: Target[];
}

/** Gather URLs and context from every kind of input. */
export async function collect(input: Input, config: Config): Promise<Collected> {
  const urls = new Set<string>();
  const extracted: Extracted = { urls: [], emails: [], phones: [] };
  const evidence: Partial<Evidence> = {};
  const emailTargets: Target[] = [];

  const merge = (e: Extracted) => {
    e.urls.forEach((u) => urls.add(u));
    extracted.emails.push(...e.emails.filter((x) => !extracted.emails.includes(x)));
    extracted.phones.push(...e.phones.filter((x) => !extracted.phones.includes(x)));
    extracted.brand ??= e.brand;
    extracted.kind ??= e.kind;
    extracted.summary ??= e.summary;
  };

  for (const u of input.urls ?? []) {
    const n = normalizeUrl(u.trim());
    if (n) urls.add(n);
  }
  if (input.text) merge(extractFromText(input.text));
  if (input.screenshot) {
    evidence.screenshot = input.screenshot;
    // Loaded on demand: the vision SDK is the heaviest dependency and most requests don't need it.
    const { extractFromImage } = await import("./ocr.ts");
    merge(await extractFromImage(input.screenshot.data, input.screenshot.mime, { anthropicKey: config.anthropicKey, model: config.visionModel }));
  }
  if (input.rawEmail) {
    evidence.rawEmail = input.rawEmail;
    const { parseEmail } = await import("./email.ts");
    const mail = await parseEmail(input.rawEmail);
    mail.urls.forEach((u) => urls.add(u));
    evidence.delivery = `E-mail from ${mail.from ?? "unknown"}${mail.subject ? `, subject "${mail.subject}"` : ""}${mail.date ? `, ${mail.date}` : ""} (original attached)`;
    for (const addr of [mail.from, mail.replyTo]) {
      const domain = addr?.split("@")[1];
      const hit = domain && MAIL_PROVIDERS.find((m) => m.domains.test(domain));
      if (hit && addr) {
        emailTargets.push({ ...hit.provider, why: [`the scam e-mail uses the mailbox ${addr}`], priority: 3, urls: [] });
      }
    }
    for (const ip of mail.senderIps) {
      const net = await lookupIp(ip);
      if (net.abuse?.email) {
        emailTargets.push({
          id: `network:${net.abuse.email.toLowerCase()}`,
          name: `${net.name ?? "Network owner"} (sending IP ${ip})`,
          role: "network",
          why: [`the scam e-mail was sent from ${ip}`],
          channels: [{ kind: "email", to: net.abuse.email }],
          priority: 4,
          urls: [],
        });
      }
    }
  }

  const list = [...urls].slice(0, MAX_URLS);
  extracted.urls = list;
  if (extracted.brand) evidence.brand = extracted.brand;
  if (!evidence.delivery && extracted.kind && extracted.kind !== "website") {
    const from = extracted.phones[0] ?? extracted.emails[0];
    evidence.delivery = `${extracted.kind.toUpperCase()}${from ? ` from ${from}` : ""}${extracted.summary ? `: ${extracted.summary}` : ""}`;
  }
  return { urls: list, extracted, evidence, emailTargets };
}

export interface Investigation {
  analyses: UrlAnalysis[];
  targets: Target[];
  reports: Report[];
  evidence: Evidence;
}

/** Analyse URLs, decide where to report, and draft the reports. Sends nothing. */
export async function investigate(
  urls: string[],
  evidence: Evidence,
  opts: { config: Config; country?: string; blockPrivate?: boolean; extraTargets?: Target[] },
): Promise<Investigation> {
  const analyses = await Promise.all(urls.slice(0, MAX_URLS).map((u) => analyzeUrl(u, { blockPrivate: opts.blockPrivate })));
  const targets = planTargets(analyses, { category: evidence.category, country: opts.country ?? opts.config.country });
  for (const t of opts.extraTargets ?? []) {
    if (!targets.some((x) => x.id === t.id)) targets.push({ ...t, urls: t.urls.length ? t.urls : urls });
  }
  targets.sort((a, b) => a.priority - b.priority);

  if (opts.config.urlscanKey) {
    const scans = await Promise.allSettled(urls.map((u) => urlscan(opts.config.urlscanKey!, u, [evidence.category])));
    evidence.scans = scans.flatMap((s) => (s.status === "fulfilled" ? [s.value] : []));
  }
  const reporter = opts.config.name && opts.config.email ? { name: opts.config.name, email: opts.config.email } : undefined;
  return { analyses, targets, reports: composeReports(targets, analyses, evidence, reporter), evidence };
}
