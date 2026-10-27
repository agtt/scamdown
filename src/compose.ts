import type { Channel, Evidence, Report, Reporter, Target, UrlAnalysis } from "./types.ts";

const KIND: Record<Evidence["category"], string> = {
  phishing: "a phishing site",
  scam: "a fraudulent (scam) site",
  malware: "malware distribution",
};

function subject(target: Target, evidence: Evidence, hosts: string[]): string {
  const tag = evidence.category === "malware" ? "Malware" : evidence.category === "scam" ? "Fraud" : "Phishing";
  const brand = evidence.brand ? ` impersonating ${evidence.brand}` : "";
  const list = hosts.slice(0, 2).join(", ") + (hosts.length > 2 ? ` +${hosts.length - 2}` : "");
  return `[${tag}] ${list}${brand}`;
}

function urlBlock(urls: string[], analyses: UrlAnalysis[]): string {
  return urls
    .map((u) => {
      const a = analyses.find((x) => x.url === u);
      if (!a) return `- ${u}`;
      const last = a.hops.at(-1);
      const lines = [`- ${u}`];
      if (a.hops.length > 1) lines.push(`  redirects: ${a.hops.map((h) => h.url).join(" -> ")}`);
      const state = last?.status ? `HTTP ${last.status}` : last?.error ? `unreachable (${last.error})` : "not checked";
      lines.push(`  status at ${a.checkedAt}: ${state}${last?.title ? `, page title "${last.title}"` : ""}`);
      const ips = a.hosts.flatMap((h) => h.ips.slice(0, 2).map((ip) => `${h.host} ${ip}${h.asn ? ` (AS${h.asn.number})` : ""}`));
      if (ips.length) lines.push(`  resolves: ${ips.join("; ")}`);
      for (const d of a.domains) {
        if (d.registeredAt) lines.push(`  ${d.domain} registered ${d.registeredAt.slice(0, 10)}${d.registrar ? ` at ${d.registrar.name}` : ""}`);
      }
      return lines.join("\n");
    })
    .join("\n");
}

function ask(target: Target): string {
  switch (target.role) {
    case "registrar":
      return "Please suspend the domain(s) under your registrar abuse obligations (ICANN RAA 3.18).";
    case "cdn":
      return "Please act under your acceptable use policy and pass this report to the origin host.";
    case "blocklist":
      return "Please add the URL(s) to your blocklist.";
    case "authority":
      return "Reported for blocking and for your records.";
    default:
      return "Please take the content down and suspend the account behind it.";
  }
}

export function composeBody(target: Target, analyses: UrlAnalysis[], evidence: Evidence, reporter?: Reporter): string {
  const parts: string[] = [];
  parts.push(`Hello ${target.name.replace(/ \(.*\)$/, "")} abuse team,`);
  parts.push(
    `I am reporting ${KIND[evidence.category]}${evidence.brand ? ` impersonating ${evidence.brand}` : ""} that uses your service. It is targeting people right now.`,
  );
  parts.push(`URL(s):\n${urlBlock(target.urls, analyses)}`);
  parts.push(`Why this concerns you:\n${target.why.map((w) => `- ${w}`).join("\n")}`);
  const context: string[] = [];
  if (evidence.delivery) context.push(`- Delivered via: ${evidence.delivery}`);
  if (evidence.notes) context.push(`- Notes: ${evidence.notes}`);
  for (const s of evidence.scans ?? []) context.push(`- Independent scan: ${s}`);
  if (evidence.screenshot) context.push(`- Screenshot attached (${evidence.screenshot.filename})`);
  if (context.length) parts.push(`Evidence:\n${context.join("\n")}`);
  parts.push(ask(target));
  parts.push(reporter ? `Thank you,\n${reporter.name}\n${reporter.email}` : "Thank you.");
  parts.push("--\nPrepared with scamdown (https://github.com/agtt/scamdown). A person reviewed this report before sending.");
  return parts.join("\n\n");
}

/** One report per target and channel. Forms and e-mails share the same text. */
export function composeReports(targets: Target[], analyses: UrlAnalysis[], evidence: Evidence, reporter?: Reporter): Report[] {
  const reports: Report[] = [];
  for (const target of targets) {
    const hosts = [...new Set(target.urls.map((u) => new URL(u).hostname))];
    const body = composeBody(target, analyses, evidence, reporter);
    for (const channel of target.channels) {
      reports.push({ target, channel, subject: subject(target, evidence, hosts), body, urls: target.urls });
    }
  }
  return reports;
}

export function mailtoLink(to: string, subject: string, body: string): string {
  return `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

export function describeChannel(c: Channel): string {
  if (c.kind === "email") return `email ${c.to}`;
  if (c.kind === "form") return `form ${c.url}`;
  return `api ${c.api}`;
}
