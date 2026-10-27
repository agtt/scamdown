import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { handle } from "./handler.ts";

const PAGE = join(dirname(fileURLToPath(import.meta.url)), "../../public/index.html");

/** Local server for `scamdown web`: the same page and API as the hosted version. */
export function serve(port: number): Promise<void> {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://localhost:${port}`);
      if (!url.pathname.startsWith("/api/")) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(await readFile(PAGE));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const response = await handle(
        new Request(url, {
          method: req.method,
          headers: { "content-type": req.headers["content-type"] ?? "application/json" },
          body: req.method === "POST" ? Buffer.concat(chunks) : undefined,
        }),
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
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
