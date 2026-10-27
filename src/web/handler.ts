import { loadConfig } from "../config.ts";
import { extractFromImage } from "../ocr.ts";
import { collect, investigate, MAX_URLS } from "../pipeline.ts";
import { netcraftUrls } from "../send/apis.ts";
import type { Category } from "../types.ts";

/**
 * HTTP API behind the web page. Stateless and send-free except Netcraft (which uses the
 * visitor's own e-mail); e-mails go out from the visitor's mail app via mailto links.
 */

const MAX_IMAGE = 6 * 1024 * 1024;
const hits = new Map<string, number[]>();

function limited(ip: string, max = 40, windowMs = 10 * 60_000): boolean {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < windowMs);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > max;
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

const isEmail = (s: unknown): s is string => typeof s === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length < 200;
const str = (s: unknown, max = 500): string | undefined => (typeof s === "string" && s.trim() ? s.trim().slice(0, max) : undefined);

export async function handle(req: Request): Promise<Response> {
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
  const config = await loadConfig();

  if (req.method === "GET" && path === "/api/config") return json({ vision: !!config.anthropicKey, maxUrls: MAX_URLS });
  if (req.method !== "POST") return json({ error: "not found" }, 404);
  if (limited(ip)) return json({ error: "Too many requests. Try again in a few minutes." }, 429);

  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  try {
    if (path === "/api/extract") {
      const image = body.image as { data?: string; mime?: string } | undefined;
      if (image?.data) {
        if (!config.anthropicKey) return json({ error: "no server OCR" }, 501);
        const data = Buffer.from(image.data, "base64");
        if (data.length > MAX_IMAGE) return json({ error: "Image too large (max 6 MB)." }, 413);
        return json(await extractFromImage(new Uint8Array(data), str(image.mime, 40) ?? "image/png", { anthropicKey: config.anthropicKey, model: config.visionModel }));
      }
      const { extracted } = await collect({ text: str(body.text, 20000) }, {});
      return json(extracted);
    }

    if (path === "/api/plan") {
      const urls = Array.isArray(body.urls) ? body.urls.filter((u): u is string => typeof u === "string").slice(0, MAX_URLS) : [];
      const category = (["phishing", "scam", "malware"].includes(body.category as string) ? body.category : "phishing") as Category;
      const { urls: clean } = await collect({ urls }, {});
      if (!clean.length) return json({ error: "No valid links." }, 400);
      const reporter = body.reporter as { name?: unknown; email?: unknown } | undefined;
      const inv = await investigate(
        clean,
        { category, brand: str(body.brand, 100), delivery: str(body.via), notes: str(body.notes, 2000) },
        {
          config: { name: str(reporter?.name, 100), email: isEmail(reporter?.email) ? reporter.email : undefined, urlscanKey: config.urlscanKey },
          country: str(body.country, 2),
          blockPrivate: true,
        },
      );
      const drafts = new Map(inv.reports.map((r) => [r.target.id, { subject: r.subject, body: r.body }]));
      return json({
        links: inv.analyses.map((a) => ({
          url: a.url,
          alive: a.alive,
          hops: a.hops.map((h) => ({ url: h.url, status: h.status, error: h.error, title: h.title })),
          hosts: a.hosts.map((h) => ({ host: h.host, ips: h.ips.slice(0, 3), asn: h.asn })),
          warnings: a.warnings,
        })),
        targets: inv.targets.map((t) => ({ ...t, draft: drafts.get(t.id) })),
        scans: inv.evidence.scans ?? [],
      });
    }

    if (path === "/api/netcraft") {
      if (!isEmail(body.email)) return json({ error: "A valid e-mail is required by Netcraft." }, 400);
      const urls = Array.isArray(body.urls) ? body.urls.filter((u): u is string => typeof u === "string" && /^https?:\/\//.test(u)).slice(0, MAX_URLS) : [];
      if (!urls.length) return json({ error: "No links." }, 400);
      return json({ result: await netcraftUrls(body.email, urls, str(body.reason, 5000) ?? "Phishing / scam site") });
    }
  } catch (e) {
    return json({ error: (e as Error).message }, 502);
  }
  return json({ error: "not found" }, 404);
}
