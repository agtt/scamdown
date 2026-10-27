import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { handle } from "./handler.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const PUBLIC = join(ROOT, "public");
const MAX_BODY = 8 * 1024 * 1024;

const STATIC: Record<string, [string, string]> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/oauth.html": ["oauth.html", "text/html; charset=utf-8"],
  "/oauth.js": ["oauth.js", "text/javascript; charset=utf-8"],
};

/** Same security headers as production: read from vercel.json so there is one source. */
async function securityHeaders(): Promise<Record<string, string>> {
  try {
    const config = JSON.parse(await readFile(join(ROOT, "vercel.json"), "utf8")) as {
      headers?: Array<{ source: string; headers: Array<{ key: string; value: string }> }>;
    };
    const all = config.headers?.find((h) => h.source === "/(.*)")?.headers ?? [];
    return Object.fromEntries(all.map((h) => [h.key, h.value]));
  } catch {
    return {};
  }
}

/** Local server for `scamdown web`: the same page and API as the hosted version. */
export async function serve(port: number): Promise<void> {
  const secure = await securityHeaders();
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://localhost:${port}`);
      const locale = url.pathname.match(/^\/locales\/([a-z]{2})\.json$/);
      const file = locale ? [`locales/${locale[1]}.json`, "application/json; charset=utf-8"] : STATIC[url.pathname];
      if (file) {
        const body = await readFile(join(PUBLIC, file[0]!)).catch(() => null);
        res.writeHead(body ? 200 : 404, { ...secure, "content-type": file[1]! });
        res.end(body ?? "");
        return;
      }
      if (!url.pathname.startsWith("/api/")) {
        res.writeHead(404, secure);
        res.end();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > MAX_BODY) {
          res.writeHead(413, secure);
          res.end();
          return;
        }
        chunks.push(chunk as Buffer);
      }
      const response = await handle(
        new Request(url, {
          method: req.method,
          headers: { "content-type": req.headers["content-type"] ?? "application/json", "x-real-ip": req.socket.remoteAddress ?? "local" },
          body: req.method === "POST" ? Buffer.concat(chunks) : undefined,
        }),
      );
      res.writeHead(response.status, { ...secure, ...Object.fromEntries(response.headers) });
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end((e as Error).message);
    }
  });
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      console.log(`scamdown web: http://localhost:${port}`);
      resolve();
    });
  });
}
