import type { Hop } from "../types.ts";
import { resolveHost } from "./dns.ts";
import { isPrivateIp } from "./ip.ts";

// Phishing kits often cloak from desktop crawlers; a phone browser sees what victims see.
const USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36";

const KEEP_HEADERS = [
  "server", "location", "content-type", "x-powered-by", "via", "cf-ray", "x-vercel-id", "x-vercel-cache",
  "x-nf-request-id", "x-github-request-id", "x-amz-cf-id", "x-amz-cf-pop", "x-served-by", "x-render-origin-server",
  "fly-request-id", "x-railway-request-id", "x-firebase-hosting", "x-goog-generation", "x-ms-request-id",
  "x-wix-request-id", "x-shopid", "x-shopify-stage", "x-cache", "x-replit-cluster",
];

const MAX_BODY = 512 * 1024;

export interface TraceOptions {
  maxHops?: number;
  timeoutMs?: number;
  /** Refuse private/loopback targets. Always on for the hosted web app. */
  blockPrivate?: boolean;
}

async function readLimited(res: Response): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    size += value.length;
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
}

function pickHeaders(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of KEEP_HEADERS) {
    const v = h.get(key);
    if (v) out[key] = v.slice(0, 200);
  }
  return out;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)));
}

/** Client-side redirects that a plain fetch does not follow. Best effort, never executes JS. */
function softRedirect(html: string, base: string): { url: string; via: "meta" | "js" } | null {
  const meta = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i);
  const js = html.match(/(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i)
    ?? html.match(/location\.(?:replace|assign)\(\s*["'](https?:\/\/[^"']+)["']\s*\)/i);
  const hit = meta?.[1] ? { raw: meta[1], via: "meta" as const } : js?.[1] ? { raw: js[1], via: "js" as const } : null;
  if (!hit) return null;
  try {
    return { url: new URL(decodeEntities(hit.raw), base).toString(), via: hit.via };
  } catch {
    return null;
  }
}

/**
 * Follow the redirect chain hop by hop without running any page code.
 * Each hop is DNS-checked first so the tool cannot be pointed at internal addresses.
 */
export async function trace(start: string, opts: TraceOptions = {}): Promise<Hop[]> {
  const maxHops = opts.maxHops ?? 10;
  const hops: Hop[] = [];
  let url = start;
  let via: Hop["via"] = "start";
  const seen = new Set<string>();

  while (hops.length < maxHops && !seen.has(url)) {
    seen.add(url);
    const hop: Hop = { url, headers: {}, via };
    hops.push(hop);
    const { hostname, protocol } = new URL(url);
    if (protocol !== "http:" && protocol !== "https:") {
      hop.error = `unsupported scheme ${protocol}`;
      break;
    }
    if (opts.blockPrivate) {
      const { ips } = await resolveHost(hostname.replace(/^\[|\]$/g, ""));
      if (ips.some(isPrivateIp)) {
        hop.error = "resolves to a private address; not fetched";
        break;
      }
    }
    let res: Response;
    try {
      res = await fetch(url, {
        redirect: "manual",
        headers: { "user-agent": USER_AGENT, accept: "text/html,*/*;q=0.8", "accept-language": "en,tr;q=0.8" },
        signal: AbortSignal.timeout(opts.timeoutMs ?? 8000),
      });
    } catch (e) {
      const err = e as Error & { cause?: { code?: string; message?: string } };
      hop.error = err.cause?.code ?? err.cause?.message ?? err.message;
      break;
    }
    hop.status = res.status;
    hop.headers = pickHeaders(res.headers);
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel().catch(() => {});
      url = new URL(location, url).toString();
      via = "http";
      continue;
    }
    const type = res.headers.get("content-type") ?? "";
    if (!type.includes("html")) {
      await res.body?.cancel().catch(() => {});
      break;
    }
    const html = await readLimited(res).catch(() => "");
    const title = html.match(/<title[^>]*>([^<]{1,300})<\/title>/i)?.[1];
    if (title) hop.title = decodeEntities(title).replace(/\s+/g, " ").trim();
    const soft = softRedirect(html, url);
    if (!soft) break;
    url = soft.url;
    via = soft.via;
  }
  return hops;
}
