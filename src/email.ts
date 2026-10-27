import PostalMime from "postal-mime";
import { extractFromText } from "./extract.ts";
import { isPrivateIp } from "./net/ip.ts";

export interface ParsedEmail {
  from?: string;
  replyTo?: string;
  subject?: string;
  date?: string;
  urls: string[];
  /** First public IP in the Received chain that is not the recipient's own provider: usually the sender. */
  senderIps: string[];
}

/** Parse a raw .eml file: sender, subject, links in text and HTML parts, and relay IPs. */
export async function parseEmail(raw: string): Promise<ParsedEmail> {
  const mail = await PostalMime.parse(raw);
  const hrefs = [...(mail.html ?? "").matchAll(/href\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1] ?? "");
  const { urls } = extractFromText([mail.text ?? "", mail.html ?? "", ...hrefs].join("\n"));

  const received = mail.headers.filter((h) => h.key === "received").map((h) => h.value);
  const senderIps: string[] = [];
  for (const line of received) {
    for (const m of line.matchAll(/\[(\d{1,3}(?:\.\d{1,3}){3})\]|\((?:[^()]*\s)?(\d{1,3}(?:\.\d{1,3}){3})\)/g)) {
      const ip = m[1] ?? m[2];
      if (ip && !isPrivateIp(ip) && !senderIps.includes(ip)) senderIps.push(ip);
    }
  }

  return {
    from: mail.from?.address,
    replyTo: mail.replyTo?.[0]?.address,
    subject: mail.subject,
    date: mail.date,
    urls,
    // Received headers are prepended, so the last public IP is closest to the origin.
    senderIps: senderIps.slice(-1),
  };
}
