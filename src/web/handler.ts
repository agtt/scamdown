import { loadConfig } from "../config.ts";
import { collect, investigate, MAX_URLS } from "../pipeline.ts";
import { netcraftUrls } from "../send/apis.ts";
import type { Category } from "../types.ts";
import { clientIp, LIMITS, rateLimit, reportKey, signPlan, VISION_DAILY, verifyPlan } from "./guard.ts";
import { getStore } from "./store.ts";

/**
 * HTTP API behind the web page. Stateless and send-free except Netcraft (sent under the operator's
 * SCAMDOWN_EMAIL, so visitors give no personal details). E-mails go out from the visitor's own mailbox:
 * their browser talks to Gmail/Outlook directly, so access tokens never reach this server.
 */

const MAX_BODY = 8 * 1024 * 1024;
const MAX_IMAGE = 6 * 1024 * 1024;
const IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];
const DAY = 86400;

const json = (data: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

const isEmail = (s: unknown): s is string => typeof s === "string" && s.length < 200 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const str = (s: unknown, max = 500): string | undefined => (typeof s === "string" && s.trim() ? s.trim().slice(0, max) : undefined);
const tooMany = (retry: number) => json({ error: "Too many requests. Try again later.", retryAfter: retry }, 429, { "retry-after": String(retry) });

export async function handle(req: Request): Promise<Response> {
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const ip = clientIp(req);
  const config = await loadConfig();

  if (req.method === "GET" && path === "/api/config") {
    return json({
      vision: !!config.anthropicKey,
      netcraft: isEmail(config.email),
      maxUrls: MAX_URLS,
      google: process.env.GOOGLE_CLIENT_ID ?? null,
      microsoft: process.env.MICROSOFT_CLIENT_ID ?? null,
    });
  }
  if (req.method !== "POST") return json({ error: "not found" }, 404);
  if (Number(req.headers.get("content-length") ?? 0) > MAX_BODY) return json({ error: "Request too large." }, 413);

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  try {
    if (path === "/api/extract") {
      const wait = await rateLimit("extract", ip, LIMITS.extract.max, LIMITS.extract.windowSec);
      if (wait) return tooMany(wait);
      const image = body.image as { data?: string; mime?: string } | undefined;
      if (image?.data) {
        if (!config.anthropicKey) return json({ error: "no server OCR" }, 501);
        const mime = str(image.mime, 40) ?? "";
        if (!IMAGE_TYPES.includes(mime)) return json({ error: "Unsupported image type." }, 415);
        const data = Buffer.from(image.data, "base64");
        if (data.length > MAX_IMAGE) return json({ error: "Image too large (max 6 MB)." }, 413);
        const perIp = await rateLimit("vision", ip, LIMITS.vision.max, LIMITS.vision.windowSec);
        const today = await getStore().incr(`vision:${new Date().toISOString().slice(0, 10)}`, DAY).catch(() => 0);
        // Over budget: the page falls back to reading the screenshot in the browser.
        if (perIp || today > VISION_DAILY) return json({ error: "no server OCR" }, 501);
        const { extractFromImage } = await import("../ocr.ts");
        return json(await extractFromImage(new Uint8Array(data), mime, { anthropicKey: config.anthropicKey, model: config.visionModel }));
      }
      const { extracted } = await collect({ text: str(body.text, 20000) }, {});
      return json(extracted);
    }

    if (path === "/api/plan") {
      const wait = await rateLimit("plan", ip, LIMITS.plan.max, LIMITS.plan.windowSec);
      if (wait) return tooMany(wait);
      const urls = Array.isArray(body.urls) ? body.urls.filter((u): u is string => typeof u === "string").slice(0, MAX_URLS) : [];
      const category = (["phishing", "scam", "malware"].includes(body.category as string) ? body.category : "phishing") as Category;
      const { urls: clean } = await collect({ urls }, {});
      if (!clean.length) return json({ error: "No valid links." }, 400);
      const inv = await investigate(
        clean,
        { category, brand: str(body.brand, 100), delivery: str(body.via), notes: str(body.notes, 2000) },
        {
          config: { urlscanKey: config.urlscanKey },
          country: str(body.country, 2),
          blockPrivate: true,
        },
      );
      const drafts = new Map(inv.reports.map((r) => [r.target.id, { subject: r.subject, body: r.body }]));
      // How often other people already reported each target in the last day: shown as a hint, never blocks.
      const counts = await getStore()
        .get(inv.targets.map((t) => reportKey(t.id, t.urls[0] ?? "")))
        .catch(() => inv.targets.map(() => 0));
      return json({
        token: signPlan(clean),
        links: inv.analyses.map((a) => ({
          url: a.url,
          alive: a.alive,
          hops: a.hops.map((h) => ({ url: h.url, status: h.status, error: h.error, title: h.title })),
          hosts: a.hosts.map((h) => ({ host: h.host, ips: h.ips.slice(0, 3), asn: h.asn })),
          warnings: a.warnings,
        })),
        targets: inv.targets.map((t, i) => ({ ...t, draft: drafts.get(t.id), recent: counts[i] ?? 0 })),
        scans: inv.evidence.scans ?? [],
      });
    }

    const planned = verifyPlan(body.token);
    const urls = Array.isArray(body.urls) ? body.urls.filter((u): u is string => typeof u === "string") : [];
    if (!planned || !urls.length || urls.some((u) => !planned.includes(u))) return json({ error: "Plan expired. Check the links again." }, 403);

    if (path === "/api/netcraft") {
      // Sent under the operator's address, so visitors stay anonymous.
      if (!isEmail(config.email)) return json({ error: "Netcraft is not set up on this server." }, 501);
      const wait = await rateLimit("netcraft", ip, LIMITS.netcraft.max, LIMITS.netcraft.windowSec);
      if (wait) return tooMany(wait);
      const result = await netcraftUrls(config.email, urls, str(body.reason, 5000) ?? "Phishing / scam site");
      await Promise.all(urls.map((u) => getStore().incr(reportKey("netcraft", u), DAY).catch(() => 0)));
      return json({ result });
    }

    if (path === "/api/sent") {
      const wait = await rateLimit("sent", ip, LIMITS.sent.max, LIMITS.sent.windowSec);
      if (wait) return tooMany(wait);
      const target = str(body.target, 200);
      if (!target) return json({ error: "target required" }, 400);
      await Promise.all(urls.map((u) => getStore().incr(reportKey(target, u), DAY)));
      return json({ ok: true });
    }
  } catch (e) {
    return json({ error: (e as Error).message }, 502);
  }
  return json({ error: "not found" }, 404);
}
