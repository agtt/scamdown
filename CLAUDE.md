# scamdown

TypeScript, Node 22.19+ at runtime, bun for dev (`bun test`, `bun src/cli.ts`). Build: `tsc` to `dist/`; imports use `.ts` extensions and are rewritten on build.

- `src/pipeline.ts` is the entry for all front ends (CLI, MCP, web): `collect` gathers URLs from text/screenshot/.eml, `investigate` analyses and drafts, `send/` delivers.
- Provider data and fingerprints: `src/providers.ts`. Only add contacts the provider publishes itself.
- Never execute or render the scam page. `src/net/trace.ts` reads at most 512 KB of HTML and blocks private IPs when `blockPrivate` is set (always on for the web handler).
- The web handler must not send anything on the visitor's behalf except Netcraft, which goes out under the operator's `SCAMDOWN_EMAIL`. Visitors never have to give a name or e-mail. Keep the page to one flow: paste, Check, Report it. Mailbox sending (Gmail/Outlook) happens in the browser (`public/app.js`); OAuth tokens never reach the server.
- Hosted version must run on free tiers: no paid API in the default path. Claude vision is optional and capped (`SCAMDOWN_VISION_DAILY`); screenshots otherwise use tesseract.js in the browser.
- Abuse endpoints (`/api/netcraft`, `/api/sent`) only accept URLs from a signed plan token (`src/web/guard.ts`). Rate limits use Upstash Redis when configured, memory otherwise.
