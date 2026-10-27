# scamdown

TypeScript, Node 20+ at runtime, bun for dev (`bun test`, `bun src/cli.ts`). Build: `tsc` to `dist/`; imports use `.ts` extensions and are rewritten on build.

- `src/pipeline.ts` is the entry for all front ends (CLI, MCP, web): `collect` gathers URLs from text/screenshot/.eml, `investigate` analyses and drafts, `send/` delivers.
- Provider data and fingerprints: `src/providers.ts`. Only add contacts the provider publishes itself.
- Never execute or render the scam page. `src/net/trace.ts` reads at most 512 KB of HTML and blocks private IPs when `blockPrivate` is set (always on for the web handler).
- The web handler must not send anything on the visitor's behalf except Netcraft with the visitor's own e-mail.
