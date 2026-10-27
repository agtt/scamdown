import { parse } from "tldts";
import { isPrivateIp } from "./net/ip.ts";
import type { Extracted } from "./types.ts";

/**
 * Big sites that show up in screenshots and message footers but are not the scam.
 * User-content subdomains on them (sites.google.com, *.github.io, ...) are matched
 * by providers.ts and kept.
 */
const NOISE_DOMAINS = new Set([
  "google.com", "apple.com", "icloud.com", "microsoft.com", "whatsapp.com", "whatsapp.net",
  "facebook.com", "instagram.com", "twitter.com", "x.com", "youtube.com", "linkedin.com",
  "telegram.org", "w3.org", "schema.org", "gstatic.com", "googleapis.com", "cloudflare.com",
  "vercel.com", "netlify.com", "github.com", "mozilla.org", "wikipedia.org",
]);

const KEEP_ON_NOISE = [
  /^sites\.google\.com$/, /^docs\.google\.com$/, /^forms\.gle$/, /^drive\.google\.com$/,
  /^storage\.googleapis\.com$/, /^firebasestorage\.googleapis\.com$/, /^raw\.githubusercontent\.com$/,
  /^gist\.github\.com$/, /^t\.me$/, /^chat\.whatsapp\.com$/, /^wa\.me$/, /^l\.facebook\.com$/,
];

/** Undo common defanging: hxxp://, example[.]com, example(.)com, [:]// */
export function refang(text: string): string {
  return text
    .replace(/\bhxxp(s?)\b/gi, "http$1")
    .replace(/\bh\*\*p(s?)\b/gi, "http$1")
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/");
}

/** Make a URL safe to paste in chat or e-mail without becoming a clickable link. */
export function defang(url: string): string {
  return url.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

const SCHEME_URL = /\bhttps?:\/\/[^\s<>"'`{}|\\^]+/gi;
const BARE_HOST = /(?<![@\w.\/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(\/[^\s<>"'`{}|\\^]*)?/gi;
const EMAIL = /[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}/gi;
const PHONE = /(?<!\w)\+?\d[\d\s().-]{8,16}\d(?!\w)/g;

function trimTail(s: string): string {
  let out = s.replace(/[.,;:!?'"»”’)\]>]+$/u, "");
  // Keep a closing paren that belongs to the URL, e.g. wiki links.
  if (s.endsWith(")") && (out.match(/\(/g)?.length ?? 0) > (out.match(/\)/g)?.length ?? 0)) out += ")";
  return out;
}

/** Normalise to an absolute URL, or null when it is not a real public hostname. */
export function normalizeUrl(raw: string): string | null {
  const candidate = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    return null;
  }
  const info = parse(u.hostname);
  if (info.isIp && isPrivateIp(u.hostname.replace(/^\[|\]$/g, ""))) return null;
  if (!info.isIp && !info.isIcann && !info.isPrivate) return null;
  if (!info.isIp && !info.domain) return null;
  u.hash = "";
  return u.toString();
}

export function isNoise(url: string): boolean {
  const host = new URL(url).hostname.toLowerCase();
  const domain = parse(host).domain;
  if (!domain || !NOISE_DOMAINS.has(domain)) return false;
  return !KEEP_ON_NOISE.some((re) => re.test(host));
}

/** Pull every URL, e-mail address and phone number out of free text (SMS, e-mail, chat, OCR). */
export function extractFromText(text: string, opts: { keepNoise?: boolean } = {}): Extracted {
  const clean = refang(text);
  const urls = new Set<string>();
  const covered: Array<[number, number]> = [];

  for (const m of clean.matchAll(SCHEME_URL)) {
    const n = normalizeUrl(trimTail(m[0]));
    if (n) urls.add(n);
    covered.push([m.index, m.index + m[0].length]);
  }
  for (const m of clean.matchAll(BARE_HOST)) {
    if (covered.some(([a, b]) => m.index >= a && m.index < b)) continue;
    const raw = trimTail(m[0]);
    // "file.txt", "v1.2" and friends: require a real ICANN suffix and a letter in the label.
    const host = (m[1] ?? "").toLowerCase();
    const info = parse(host);
    if (!info.isIcann || !info.domainWithoutSuffix || /^\d+$/.test(info.domainWithoutSuffix)) continue;
    const n = normalizeUrl(raw);
    if (n) urls.add(n);
  }

  const emails = [...new Set([...clean.matchAll(EMAIL)].map((m) => m[0].toLowerCase()))];
  const phones = [...new Set([...clean.matchAll(PHONE)].map((m) => m[0].replace(/[^\d+]/g, "")))].filter(
    (p) => p.replace("+", "").length >= 10,
  );

  // An e-mail address also matches as a bare host; drop those.
  const emailDomains = new Set(emails.map((e) => e.split("@")[1]));
  const list = [...urls].filter((u) => {
    const parsed = new URL(u);
    if (parsed.pathname === "/" && !parsed.search && emailDomains.has(parsed.hostname)) return false;
    return opts.keepNoise || !isNoise(u);
  });

  return { urls: list, emails, phones };
}
