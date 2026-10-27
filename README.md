# scamdown

Report a scam or phishing link to everyone who can take it down, in one go.

Give it a link, the text of a scam SMS, a screenshot, or a phishing e-mail. scamdown follows the redirects, works out who is involved (blocklists, host, CDN, registrar, network owner), writes a report for each with the evidence they ask for, and sends what it can automatically. The rest open as pre-filled forms or e-mails.

[Türkçe](docs/README.tr.md)

```
$ scamdown report "hxxps://ptt-kargo-odeme[.]xyz/takip"

https://ptt-kargo-odeme.xyz/takip  live
  ptt-kargo-odeme.xyz  104.21.48.1  AS13335 CLOUDFLARENET
  ! ptt-kargo-odeme.xyz was registered 2 day(s) ago.

Where to report (first = fastest protection)
  Netcraft                             api netcraft
  Google Safe Browsing                 form https://safebrowsing.google.com/safebrowsing/report_phish/
  Microsoft SmartScreen                form https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
  APWG (Anti-Phishing Working Group)   email reportphishing@apwg.org
  Cloudflare (proxy/CDN)               form https://abuse.cloudflare.com/phishing
    ptt-kargo-odeme.xyz: HTTP header cf-ray: 8d2f...-IST; ptt-kargo-odeme.xyz: HTTP header server: cloudflare
  NameSilo, LLC (registrar)            email abuse@namesilo.com
    ptt-kargo-odeme.xyz is registered with NameSilo, LLC (IANA 1479), registered 2 day(s) ago

Dry run. Nothing was sent. Re-run with --send.
```

## Why this order

1. **Blocklists first.** Netcraft, Google Safe Browsing and Microsoft SmartScreen put a warning page in front of the site in every major browser, often within an hour. That protects people before any takedown happens.
2. **Host / platform.** Vercel, Netlify, GitHub Pages, Firebase, AWS and others can delete the deployment.
3. **Registrar.** Suspending the domain kills the site, every subdomain and its mail. Registrars accredited by ICANN must investigate abuse reports (RAA 3.18).
4. **CDN.** Cloudflare can't delete a site it only proxies, but it forwards the report to the real host and shows phishing warnings.
5. **Network owner.** For sites on a plain VPS, the IP owner's abuse contact (from RDAP) is the one that acts.

## Install

```sh
npx scamdown report <link>          # no install
npm i -g scamdown                   # or bun add -g scamdown
scamdown init                       # name, e-mail, optional SMTP and API keys
```

Node 20 or newer.

## Use

```sh
scamdown report https://example-scam.com                 # dry run: shows the plan
scamdown report https://example-scam.com --send          # send
scamdown report -i sms-screenshot.png --country TR --send
scamdown report -e phishing.eml --send                   # whole e-mail goes to Netcraft too
pbpaste | scamdown report - --brand "Garanti BBVA" --via "SMS from +90 850 000 0000"
scamdown check                                           # which reported links are down now
```

How sending works:

| Channel | How |
|---|---|
| Netcraft | Public API, no key. You get status mails from Netcraft. |
| E-mail (registrar, network, APWG, ...) | Your SMTP account if set (`smtps://user:app-password@smtp.gmail.com:465`), otherwise your mail app opens with the report filled in. The screenshot and .eml are attached over SMTP. |
| Web forms (Google, Microsoft, Vercel, Cloudflare, ...) | The form opens and the report text is on your clipboard. Most of these have a captcha, so a person submits them. |
| Cloudflare API | Optional. Needs a token with "Trust and Safety Write" and Cloudflare enabling abuse reports on your account. |

Nothing is sent without `--send`, and you are asked to confirm. The same link is not reported to the same place twice within three days.

## Screenshots

`-i shot.png` reads the links out of a screenshot. With `ANTHROPIC_API_KEY` set, Claude reads it (handles chat bubbles, cut-off links, and also picks up the sender and impersonated brand). Without a key, the local `tesseract` binary is used.

## Web page

```sh
scamdown web          # http://localhost:8787
```

Paste a screenshot or a message, get the list of places with one-click buttons. The same page deploys to Vercel as is (`vercel deploy`). The hosted version does not send e-mail on anyone's behalf: e-mail buttons open the visitor's own mail app, and the only thing the server submits is Netcraft, when the visitor presses that button with their own address. Screenshots are read in the browser with tesseract.js, or by Claude if the deployment has `ANTHROPIC_API_KEY`.

## MCP server

For Claude Desktop, Claude Code, Cursor and other MCP clients. Drop a screenshot in the chat and say "report this".

```json
{
  "mcpServers": {
    "scamdown": { "command": "npx", "args": ["-y", "scamdown", "mcp"] }
  }
}
```

Claude Code: `claude mcp add scamdown -- npx -y scamdown mcp`

Tools: `extract_links`, `check_link`, `plan_reports`, `send_reports` (needs explicit confirmation), `check_status`. It uses the same `~/.scamdown/config.json` as the CLI.

## Configuration

`scamdown init` writes `~/.scamdown/config.json` (mode 600). Environment variables override it:

| Variable | Purpose |
|---|---|
| `SCAMDOWN_NAME`, `SCAMDOWN_EMAIL` | Who the report is from. Abuse desks reply here. |
| `SCAMDOWN_SMTP_URL`, `SCAMDOWN_SMTP_FROM` | Send e-mails directly. |
| `SCAMDOWN_COUNTRY` | Add national reporting: `TR` (USOM), `GB` (NCSC), `US` (FTC). |
| `URLSCAN_API_KEY` | Adds a public urlscan.io scan link to every report, so desks can see the page without visiting it. |
| `ANTHROPIC_API_KEY`, `SCAMDOWN_VISION_MODEL` | Read screenshots with Claude (default `claude-opus-5-5`). |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | Cloudflare abuse API instead of the form. |

## What it checks

- Redirect chain, including meta refresh and simple JavaScript redirects, without running page code. URL shorteners are reported too.
- DNS through public resolvers (1.1.1.1, 8.8.8.8), so an ISP block or sinkhole does not hide the real host.
- IP owner and ASN (Team Cymru), domain registrar, abuse contact, creation date and hold status (RDAP).
- Platform fingerprints: hostname, CNAME, IP range, response headers. See [`src/providers.ts`](src/providers.ts).
- Requests use a mobile browser user agent, because many phishing kits hide from desktop crawlers.
- Private and internal addresses are never fetched.

## Using it responsibly

Reports carry your name and e-mail. False reports waste the time of the people who take scams down and can get your address ignored. Report what you have actually seen, add how it reached you, and don't report the same link over and over: abuse desks treat that as spam. scamdown never sends your details to the site owner.

If you lost money: call your bank first, then the police.

## Contributing

The most useful contribution is keeping abuse contacts correct and adding platforms. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

If scamdown helped take something down, you can [buy me a coffee](https://buymeacoffee.com/agtt) or [sponsor on GitHub](https://github.com/sponsors/agtt). It pays for the hosted page and keeps the contact list maintained.

## License

MIT
