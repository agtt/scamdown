import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { analyzeUrl } from "./analyze.ts";
import { loadConfig } from "./config.ts";
import { extractFromText } from "./extract.ts";
import { readHistory } from "./history.ts";
import { collect, investigate } from "./pipeline.ts";
import { chooseChannel, sendReports } from "./send/index.ts";
import type { Category } from "./types.ts";

const caseShape = {
  text: z.string().optional().describe("Links or the full scam message (SMS, chat, e-mail text). Defanged links are fine."),
  urls: z.array(z.string()).optional().describe("Links, if you already extracted them"),
  category: z.enum(["phishing", "scam", "malware"]).default("phishing"),
  brand: z.string().optional().describe("Who is being impersonated"),
  via: z.string().optional().describe('How it reached people, e.g. "SMS from +90 555 000 0000 on 2026-10-27"'),
  notes: z.string().optional(),
  country: z.string().optional().describe("ISO country for national reporting: TR, GB, US"),
};

type CaseArgs = {
  text?: string;
  urls?: string[];
  category: Category;
  brand?: string;
  via?: string;
  notes?: string;
  country?: string;
};

async function prepare(args: CaseArgs) {
  const config = await loadConfig();
  const collected = await collect({ text: args.text, urls: args.urls }, config);
  if (!collected.urls.length) throw new Error("No links found in the input.");
  const evidence = { ...collected.evidence, category: args.category, brand: args.brand, delivery: args.via, notes: args.notes };
  const inv = await investigate(collected.urls, evidence, { config, country: args.country });
  return { config, inv };
}

const text = (value: unknown) => ({ content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] });

export async function startMcp(): Promise<void> {
  const server = new McpServer(
    { name: "scamdown", version: "0.1.0" },
    {
      instructions:
        "Report scam and phishing links. If the user shares a screenshot, read the links from it yourself and pass them as text. " +
        "Always call plan_reports first and show the user where reports will go. Call send_reports only after the user explicitly agrees.",
    },
  );

  server.registerTool(
    "extract_links",
    {
      title: "Extract links",
      description: "Find links, e-mail addresses and phone numbers in a scam message. Undoes defanging (hxxp, [.]).",
      inputSchema: { text: z.string() },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ text: input }) => text(extractFromText(input)),
  );

  server.registerTool(
    "check_link",
    {
      title: "Check a link",
      description: "Follow redirects and identify host, CDN, registrar, IP owner and domain age for one link. Never runs page code.",
      inputSchema: { url: z.string() },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ url }) => {
      const a = await analyzeUrl(/^https?:/i.test(url) ? url : `http://${url}`);
      return text({
        url: a.url,
        alive: a.alive,
        redirects: a.hops.map((h) => ({ url: h.url, status: h.status, error: h.error, title: h.title })),
        hosts: a.hosts.map((h) => ({ host: h.host, ips: h.ips, cnames: h.cnames, asn: h.asn, nameservers: h.nameservers })),
        domains: a.domains,
        warnings: a.warnings,
      });
    },
  );

  server.registerTool(
    "plan_reports",
    {
      title: "Plan reports",
      description: "Work out every place these links should be reported (blocklists, host, CDN, registrar, network) and draft each report. Sends nothing.",
      inputSchema: caseShape,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async (args) => {
      const { config, inv } = await prepare(args as CaseArgs);
      return text({
        links: inv.analyses.map((a) => ({ url: a.url, alive: a.alive, warnings: a.warnings })),
        targets: inv.targets.map((t) => {
          const ch = chooseChannel(t.channels, config);
          return { name: t.name, role: t.role, why: t.why, channel: ch, automatic: ch?.kind !== "form" && !(ch?.kind === "email" && !config.smtpUrl), tip: t.tip };
        }),
        draft: inv.reports[0] ? { subject: inv.reports[0].subject, body: inv.reports[0].body } : null,
        reporter: config.email ? `${config.name} <${config.email}>` : "not set: run `scamdown init`",
      });
    },
  );

  server.registerTool(
    "send_reports",
    {
      title: "Send reports",
      description:
        "Send the planned reports through APIs (Netcraft, Cloudflare) and SMTP. Web forms are returned with their pre-written text for the user to submit. " +
        "Only call after the user has seen plan_reports and agreed.",
      inputSchema: { ...caseShape, confirmed: z.literal(true).describe("The user explicitly agreed to send") },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async (args) => {
      const { config, inv } = await prepare(args as CaseArgs);
      const results = await sendReports(inv.reports, { config, evidence: inv.evidence });
      return text(
        results.map((r) => ({
          target: r.report.target.name,
          status: r.status,
          detail: r.detail,
          ...(r.status === "manual" ? { open: r.report.channel, subject: r.report.subject, body: r.report.body } : {}),
        })),
      );
    },
  );

  server.registerTool(
    "check_status",
    {
      title: "Is it down yet?",
      description: "Re-check links (default: everything reported before) and say which are still live.",
      inputSchema: { urls: z.array(z.string()).optional() },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ urls }) => {
      const history = await readHistory();
      const list = urls?.length ? urls : [...new Set(history.filter((h) => h.ok).map((h) => h.url))];
      const rows = await Promise.all(
        list.map(async (u) => {
          const a = await analyzeUrl(u, { maxHops: 5 });
          return { url: u, live: a.alive && !a.domains.some((d) => d.onHold), firstReported: history.find((h) => h.url === u && h.ok)?.at };
        }),
      );
      return text(rows);
    },
  );

  await server.connect(new StdioServerTransport());
}
