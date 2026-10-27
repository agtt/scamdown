#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { basename, extname } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { analyzeUrl } from "./analyze.ts";
import { describeChannel, mailtoLink } from "./compose.ts";
import { loadConfig, saveConfig, type Config } from "./config.ts";
import { readHistory } from "./history.ts";
import { collect, investigate } from "./pipeline.ts";
import { chooseChannel, sendReports } from "./send/index.ts";
import type { Category, Report, ScreenshotFile } from "./types.ts";

const HELP = `scamdown: report scam and phishing links to everyone who can take them down

Usage
  scamdown report <link | text | ->  [options]   find where to report, draft and (with --send) send
  scamdown init                                 save your name, e-mail and optional SMTP/API keys
  scamdown check [url...]                       is it down yet? (defaults to everything you reported)
  scamdown history                              what you reported, where, and when
  scamdown web [--port 8787]                    local web page: paste a screenshot, get reports
  scamdown mcp                                  MCP server (stdio) for Claude, Cursor and others

Report options
  -i, --image <file>      screenshot of the SMS / chat / page (links are read from it)
  -e, --eml <file>        a phishing e-mail saved as .eml
  -c, --category <type>   phishing | scam | malware            (default phishing)
  -b, --brand <name>      who is being impersonated, e.g. "USPS"
  -v, --via <text>        how it arrived, e.g. "SMS from +1 202 555 0143"
  -n, --notes <text>      anything else the abuse desk should know
      --country <CC>      add national reporting (TR, GB, US)
      --send              actually send (default is a dry run)
  -y, --yes               do not ask before sending
      --force             send even if already reported in the last 3 days
      --json              print machine-readable output

Examples
  scamdown report "hxxps://usps-redelivery[.]xyz/pay"
  scamdown report -i sms.png --country US --send
  pbpaste | scamdown report - --send`;

const tty = process.stdout.isTTY;
const c = (code: number) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c(1);
const dim = c(2);
const red = c(31);
const green = c(32);
const yellow = c(33);

function fail(msg: string): never {
  console.error(red(msg));
  process.exit(1);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function loadScreenshot(path: string): Promise<ScreenshotFile> {
  const ext = extname(path).toLowerCase();
  const mime = ext === ".jpg" || ext === ".jpeg" ? "image/jpeg" : ext === ".webp" ? "image/webp" : ext === ".gif" ? "image/gif" : "image/png";
  return { filename: basename(path), mime, data: new Uint8Array(await readFile(path)) };
}

function runQuiet(cmd: string, args: string[], input?: string): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: [input ? "pipe" : "ignore", "ignore", "ignore"] });
    p.on("error", () => resolve(false));
    p.on("close", (code) => resolve(code === 0));
    if (input) p.stdin?.end(input);
  });
}

async function copy(text: string): Promise<boolean> {
  if (process.platform === "darwin") return runQuiet("pbcopy", [], text);
  if (process.platform === "win32") return runQuiet("clip", [], text);
  return (await runQuiet("wl-copy", [], text)) || runQuiet("xclip", ["-selection", "clipboard"], text);
}

function openUrl(url: string): Promise<boolean> {
  if (process.platform === "darwin") return runQuiet("open", [url]);
  // Not `cmd /c start`: cmd would treat the "&" in mailto links as a command separator.
  if (process.platform === "win32") return runQuiet("rundll32", ["url.dll,FileProtocolHandler", url]);
  return runQuiet("xdg-open", [url]);
}

async function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

async function report(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      image: { type: "string", short: "i" },
      eml: { type: "string", short: "e" },
      category: { type: "string", short: "c", default: "phishing" },
      brand: { type: "string", short: "b" },
      via: { type: "string", short: "v" },
      notes: { type: "string", short: "n" },
      country: { type: "string" },
      send: { type: "boolean", default: false },
      yes: { type: "boolean", short: "y", default: false },
      force: { type: "boolean", default: false },
      json: { type: "boolean", default: false },
    },
  });
  const category = values.category as Category;
  if (!["phishing", "scam", "malware"].includes(category)) fail(`Unknown category "${category}".`);

  const config = await loadConfig();
  let text = positionals.filter((p) => p !== "-").join("\n");
  if (positionals.includes("-") || (!positionals.length && !values.image && !values.eml && !process.stdin.isTTY)) text += `\n${await readStdin()}`;

  const collected = await collect(
    {
      text,
      screenshot: values.image ? await loadScreenshot(values.image) : undefined,
      rawEmail: values.eml ? await readFile(values.eml, "utf8") : undefined,
    },
    config,
  );
  if (!collected.urls.length && !collected.emailTargets.length) fail("No links found. Pass a URL, text containing one, --image or --eml.");

  const evidence = {
    ...collected.evidence,
    category,
    brand: values.brand ?? collected.evidence.brand,
    delivery: values.via ?? collected.evidence.delivery,
    notes: values.notes,
  };
  if (!values.json) console.log(dim(`Checking ${collected.urls.length} link(s)...`));
  const inv = await investigate(collected.urls, evidence, { config, country: values.country, extraTargets: collected.emailTargets });

  if (values.json && !values.send) {
    const { screenshot, rawEmail, ...ev } = inv.evidence;
    console.log(JSON.stringify({ analyses: inv.analyses, targets: inv.targets, reports: inv.reports.map(({ target, ...r }) => ({ target: target.id, ...r })), evidence: ev }, null, 2));
    return;
  }

  for (const a of inv.analyses) {
    console.log(`\n${bold(a.url)}  ${a.alive ? red("live") : green("not responding")}`);
    if (a.hops.length > 1) console.log(dim(`  ${a.hops.map((h) => `${h.url} ${h.status ?? h.error ?? ""}`).join("\n  -> ")}`));
    for (const h of a.hosts) console.log(dim(`  ${h.host}  ${h.ips.slice(0, 2).join(", ") || "no address"}${h.asn ? `  AS${h.asn.number} ${h.asn.name}` : ""}`));
    for (const w of a.warnings) console.log(yellow(`  ! ${w}`));
  }

  if (!inv.targets.length) {
    console.log(`\n${green("Nothing to report:")} none of these links resolve any more.`);
    return;
  }
  console.log(`\n${bold("Where to report")} ${dim("(first = fastest protection)")}`);
  const width = Math.min(40, Math.max(...inv.targets.map((t) => t.name.length)) + 2);
  for (const t of inv.targets) {
    const ch = chooseChannel(t.channels, config);
    console.log(`  ${bold(t.name.padEnd(width))} ${dim(ch ? describeChannel(ch) : "")}`);
    if (t.role !== "blocklist" && t.role !== "authority") console.log(dim(`    ${t.why.slice(0, 2).join("; ")}`));
  }

  if (!values.send) {
    console.log(`\n${yellow("Dry run.")} Nothing was sent. Re-run with --send. Drafts: --json`);
    if (!config.email) console.log(dim("Run `scamdown init` first so reports carry your name and reply address."));
    return;
  }
  if (!values.yes && process.stdin.isTTY) {
    const auto = inv.targets.filter((t) => chooseChannel(t.channels, config)?.kind !== "form").length;
    const answer = await ask(`\nSend ${auto} automatic report(s) and walk through ${inv.targets.length - auto} form(s)? [y/N] `);
    if (!/^y(es)?$/i.test(answer)) return;
  }

  const interactive = process.stdin.isTTY && !values.yes;
  const results = await sendReports(inv.reports, {
    config,
    evidence: inv.evidence,
    force: values.force,
    onManual: async (r: Report) => {
      if (!interactive) return;
      const target = r.channel.kind === "form" ? r.channel.url : r.channel.kind === "email" ? mailtoLink(r.channel.to, r.subject, r.body) : "";
      const copied = await copy(`${r.subject}\n\n${r.body}`);
      console.log(`\n${bold(r.target.name)}: ${r.channel.kind === "email" ? r.channel.to : target}`);
      if (r.channel.kind === "form" && r.channel.note) console.log(dim(`  ${r.channel.note}`));
      console.log(dim(copied ? "  Report text copied. Paste it into the form, attach the screenshot if there is a field." : `  Report text:\n${r.body}`));
      await openUrl(target);
      await ask(dim("  Press Enter when done (or to skip)... "));
    },
  });

  console.log("");
  for (const r of results) {
    const mark = r.status === "sent" ? green("sent   ") : r.status === "failed" ? red("failed ") : r.status === "manual" ? yellow("manual ") : dim("skipped");
    console.log(`  ${mark} ${r.report.target.name}  ${dim(r.detail)}`);
  }
  if (values.json) console.log(JSON.stringify(results.map((r) => ({ target: r.report.target.id, channel: r.report.channel, status: r.status, detail: r.detail }))));
  console.log(dim("\nCheck later with: scamdown check"));
}

async function init(): Promise<void> {
  const current = await loadConfig();
  const q = async (label: string, key: keyof Config, hint = "") => {
    const v = await ask(`${label}${hint ? dim(` (${hint})`) : ""}${current[key] ? dim(` [${key.includes("Key") || key.includes("Token") || key === "smtpUrl" ? "set" : current[key]}]`) : ""}: `);
    if (v) current[key] = v;
  };
  console.log("Abuse desks reply to this address. Use a mailbox you read.\n");
  await q("Your name", "name");
  await q("Your e-mail", "email");
  await q("Country code for national reporting", "country", "TR, GB, US or empty");
  await q("SMTP URL to send e-mails yourself", "smtpUrl", "smtps://user:app-password@smtp.gmail.com:465, empty = open your mail app");
  await q("urlscan.io API key", "urlscanKey", "optional, adds a safe evidence link");
  await q("Anthropic API key", "anthropicKey", "optional, reads screenshots");
  await q("Cloudflare API token", "cloudflareToken", "optional, needs abuse-report access");
  if (current.cloudflareToken) await q("Cloudflare account id", "cloudflareAccountId");
  console.log(green(`Saved ${await saveConfig(current)}`));
}

async function check(urls: string[]): Promise<void> {
  const history = await readHistory();
  const list = urls.length ? urls : [...new Set(history.filter((h) => h.ok).map((h) => h.url))];
  if (!list.length) fail("Nothing to check. Pass a URL or report something first.");
  for (const url of list) {
    const a = await analyzeUrl(url, { maxHops: 5 });
    const first = history.find((h) => h.url === url && h.ok)?.at;
    const since = first ? dim(` reported ${Math.round((Date.now() - Date.parse(first)) / 3_600_000)}h ago`) : "";
    const held = a.domains.some((d) => d.onHold);
    console.log(`${a.alive && !held ? red("live") : green("down")}  ${url}${since}${held ? dim(" (registry hold)") : ""}`);
  }
}

async function showHistory(): Promise<void> {
  const history = await readHistory();
  if (!history.length) return void console.log("No reports yet.");
  for (const h of history) console.log(`${dim(h.at.slice(0, 16).replace("T", " "))}  ${h.ok ? green("ok") : red("x ")}  ${h.target.padEnd(28)} ${h.url}`);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "report":
      return report(rest);
    case "init":
      return init();
    case "check":
      return check(rest);
    case "history":
      return showHistory();
    case "web": {
      const { values } = parseArgs({ args: rest, options: { port: { type: "string", default: "8787" } } });
      const { serve } = await import("./web/node-server.ts");
      return serve(Number(values.port));
    }
    case "mcp": {
      const { startMcp } = await import("./mcp.ts");
      return startMcp();
    }
    case undefined:
    case "-h":
    case "--help":
    case "help":
      return void console.log(HELP);
    default:
      // `scamdown <link>` is the common case: treat it as report.
      return report([cmd, ...rest]);
  }
}

main().catch((e: Error) => fail(e.message));
