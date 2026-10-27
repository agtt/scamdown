import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { getStore } from "./store.ts";

/** Requests per window, per client IP. */
export const LIMITS = {
  plan: { max: 30, windowSec: 600 },
  extract: { max: 60, windowSec: 600 },
  vision: { max: 10, windowSec: 3600 },
  netcraft: { max: 20, windowSec: 3600 },
  sent: { max: 120, windowSec: 3600 },
} as const;

/** Screenshots read by Claude per day across all visitors: the operator pays for these. */
export const VISION_DAILY = Number(process.env.SCAMDOWN_VISION_DAILY ?? 500);

export function clientIp(req: Request): string {
  // Vercel sets x-real-ip itself; a client can't spoof it. x-forwarded-for is the fallback for other proxies.
  return req.headers.get("x-real-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
}

/** Fixed-window limit. Returns seconds to wait, or 0 when allowed. Fails open if the store is down. */
export async function rateLimit(name: string, id: string, max: number, windowSec: number): Promise<number> {
  const window = Math.floor(Date.now() / 1000 / windowSec);
  try {
    const n = await getStore().incr(`rl:${name}:${id}:${window}`, windowSec);
    return n > max ? (window + 1) * windowSec - Math.floor(Date.now() / 1000) : 0;
  } catch {
    return 0;
  }
}

// Without SCAMDOWN_SECRET tokens only work on the instance that issued them: fine locally, set it on Vercel.
const SECRET = process.env.SCAMDOWN_SECRET ?? randomBytes(32).toString("hex");
const b64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/**
 * The plan endpoint signs the URLs it analysed. Endpoints that act on them (Netcraft, report counters)
 * only accept URLs from a recent signed plan, so the server can't be used as an open relay.
 */
export function signPlan(urls: string[], ttlSec = 3600): string {
  const payload = b64(JSON.stringify({ u: urls, e: Math.floor(Date.now() / 1000) + ttlSec }));
  return `${payload}.${b64(createHmac("sha256", SECRET).update(payload).digest())}`;
}

export function verifyPlan(token: unknown): string[] | null {
  if (typeof token !== "string") return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = createHmac("sha256", SECRET).update(payload).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString()) as { u: string[]; e: number };
    return data.e > Date.now() / 1000 && Array.isArray(data.u) ? data.u : null;
  } catch {
    return null;
  }
}

/** Key for "how many people reported this URL to this place in the last day". No URL is stored in clear. */
export function reportKey(targetId: string, url: string): string {
  return `sent:${targetId}:${createHash("sha256").update(url).digest("base64url").slice(0, 22)}`;
}
