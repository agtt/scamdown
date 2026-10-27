import type { Category, Channel, HostInfo, Role } from "./types.ts";

/**
 * How to recognise a service from DNS, network and HTTP data, and where it takes abuse reports.
 * Contacts were checked against each provider's own pages; open a PR when one changes.
 */
export interface Provider {
  id: string;
  name: string;
  role: Role;
  match: {
    hostSuffix?: string[];
    cnameSuffix?: string[];
    nsSuffix?: string[];
    asn?: number[];
    ipPrefix?: string[];
    header?: Array<[string, RegExp]>;
  };
  channels: Channel[];
  tip?: string;
}

const email = (to: string): Channel => ({ kind: "email", to });
const form = (url: string, note?: string): Channel => ({ kind: "form", url, note });

export const PROVIDERS: Provider[] = [
  {
    id: "vercel",
    name: "Vercel",
    role: "host",
    match: {
      hostSuffix: ["vercel.app", "now.sh"],
      cnameSuffix: ["vercel-dns.com"],
      ipPrefix: ["76.76.21."],
      header: [["server", /^vercel$/i], ["x-vercel-id", /./]],
    },
    channels: [form("https://vercel.com/abuse"), email("abuse@vercel.com")],
    tip: "Vercel deploys are often re-created under a new *.vercel.app name; re-check the brand after takedown.",
  },
  {
    id: "cloudflare-pages",
    name: "Cloudflare Pages / Workers / R2",
    role: "host",
    match: { hostSuffix: ["pages.dev", "workers.dev", "r2.dev"] },
    channels: [form("https://abuse.cloudflare.com/phishing"), { kind: "api", api: "cloudflare" }],
    tip: "Cloudflare hosts this content itself, so it can remove it directly.",
  },
  {
    id: "cloudflare",
    name: "Cloudflare (proxy/CDN)",
    role: "cdn",
    match: { asn: [13335, 209242], header: [["cf-ray", /./], ["server", /^cloudflare$/i]] },
    channels: [form("https://abuse.cloudflare.com/phishing"), { kind: "api", api: "cloudflare" }],
    tip: "Cloudflare forwards phishing reports to the real host and shows you who that is; they also add phishing warnings in front of the site.",
  },
  {
    id: "cloudflare-dns",
    name: "Cloudflare (DNS)",
    role: "dns",
    match: { nsSuffix: ["ns.cloudflare.com"] },
    channels: [form("https://abuse.cloudflare.com/phishing")],
  },
  {
    id: "netlify",
    name: "Netlify",
    role: "host",
    match: {
      hostSuffix: ["netlify.app", "netlify.com"],
      cnameSuffix: ["netlify.app", "netlifyglobalcdn.com"],
      header: [["server", /^netlify/i], ["x-nf-request-id", /./]],
    },
    channels: [email("fraud@netlify.com")],
  },
  {
    id: "github",
    name: "GitHub Pages",
    role: "host",
    match: {
      hostSuffix: ["github.io", "githubusercontent.com"],
      cnameSuffix: ["github.io"],
      ipPrefix: ["185.199.108.", "185.199.109.", "185.199.110.", "185.199.111."],
      header: [["x-github-request-id", /./]],
    },
    channels: [form("https://support.github.com/contact/report-abuse")],
  },
  {
    id: "firebase",
    name: "Firebase Hosting (Google)",
    role: "host",
    match: { hostSuffix: ["web.app", "firebaseapp.com"], header: [["x-firebase-hosting", /./]] },
    channels: [form("https://firebase.google.com/support/troubleshooter/report")],
  },
  {
    id: "google-docs",
    name: "Google Sites / Forms / Drive",
    role: "platform",
    match: {
      hostSuffix: [
        "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
        "storage.googleapis.com", "firebasestorage.googleapis.com",
      ],
    },
    channels: [form("https://support.google.com/docs/contact/abuse", "Needs a Google login.")],
  },
  {
    id: "blogger",
    name: "Blogger",
    role: "platform",
    match: { hostSuffix: ["blogspot.com"] },
    channels: [form("https://www.blogger.com/report")],
  },
  {
    id: "render",
    name: "Render",
    role: "host",
    match: { hostSuffix: ["onrender.com"], header: [["x-render-origin-server", /./]] },
    channels: [email("abuse@render.com")],
  },
  {
    id: "aws",
    name: "Amazon Web Services",
    role: "host",
    match: {
      hostSuffix: ["amazonaws.com", "cloudfront.net", "amplifyapp.com", "awsapprunner.com"],
      cnameSuffix: ["cloudfront.net", "amazonaws.com", "amplifyapp.com"],
      asn: [16509, 14618],
      header: [["x-amz-cf-id", /./]],
    },
    channels: [form("https://repost.aws/knowledge-center/report-aws-abuse"), email("trustandsafety@support.aws.com")],
  },
  {
    id: "azure",
    name: "Microsoft Azure",
    role: "host",
    match: {
      hostSuffix: ["azurewebsites.net", "web.core.windows.net", "blob.core.windows.net", "azureedge.net", "azurestaticapps.net"],
      cnameSuffix: ["azurewebsites.net", "azureedge.net", "azurefd.net", "trafficmanager.net"],
      asn: [8075],
    },
    channels: [form("https://msrc.microsoft.com/report/abuse")],
  },
  {
    id: "digitalocean",
    name: "DigitalOcean",
    role: "host",
    match: { hostSuffix: ["ondigitalocean.app"], asn: [14061] },
    channels: [form("https://www.digitalocean.com/company/contact/abuse")],
  },
  {
    id: "ngrok",
    name: "ngrok",
    role: "host",
    match: { hostSuffix: ["ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-free.dev"] },
    channels: [form("https://ngrok.com/abuse"), email("abuse@ngrok.com")],
  },
  {
    id: "wix",
    name: "Wix",
    role: "host",
    match: { hostSuffix: ["wixsite.com", "wixstudio.com", "editorx.io"], header: [["x-wix-request-id", /./]] },
    channels: [form("https://www.wix.com/abuse")],
  },
  {
    id: "weebly",
    name: "Weebly / Square Online",
    role: "host",
    match: { hostSuffix: ["weebly.com", "weeblysite.com", "square.site"] },
    channels: [form("https://www.weebly.com/abuse")],
  },
  {
    id: "shopify",
    name: "Shopify",
    role: "host",
    match: { hostSuffix: ["myshopify.com"], header: [["x-shopid", /./], ["x-shopify-stage", /./]] },
    channels: [form("https://www.shopify.com/legal/tools/report-an-issue")],
  },
  {
    id: "wordpress-com",
    name: "WordPress.com",
    role: "host",
    match: { hostSuffix: ["wordpress.com"] },
    channels: [form("https://wordpress.com/abuse/?report_type=abuse")],
  },
  {
    id: "hostinger",
    name: "Hostinger",
    role: "host",
    match: { hostSuffix: ["hostingersite.com", "000webhostapp.com"], asn: [47583] },
    channels: [form("https://www.hostinger.com/report-abuse"), email("abuse@hostinger.com")],
  },
  {
    id: "telegram",
    name: "Telegram",
    role: "platform",
    match: { hostSuffix: ["t.me", "telegram.me", "telegra.ph"] },
    channels: [email("abuse@telegram.org")],
    tip: "Inside the app you can also report the channel/user (⋮ → Report → Scam).",
  },
  {
    id: "tinyurl",
    name: "TinyURL",
    role: "shortener",
    match: { hostSuffix: ["tinyurl.com"] },
    channels: [form("https://tinyurl.com/app/report-abuse")],
  },
];

/**
 * Domains that belong to a public service, not to the scammer: never report them to their
 * registrar or network. The redirect target behind a short link is analysed on its own.
 */
export const SHARED_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "ow.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly",
  "s.id", "tiny.cc", "buff.ly", "lnkd.in", "qrco.de", "linktr.ee", "google.com", "facebook.com",
]);

/** Blocklists: browsers and mail filters start warning people within minutes, even before a takedown. */
export function blocklists(category: Category): Provider[] {
  const list: Provider[] = [
    {
      id: "netcraft",
      name: "Netcraft",
      role: "blocklist",
      match: {},
      channels: [{ kind: "api", api: "netcraft" }, form("https://report.netcraft.com/report")],
      tip: "Feeds browser and mail blocklists and runs its own takedown requests to hosts and registrars.",
    },
    {
      id: "google-safebrowsing",
      name: "Google Safe Browsing",
      role: "blocklist",
      match: {},
      channels: [
        form(
          category === "malware"
            ? "https://safebrowsing.google.com/safebrowsing/report_badware/"
            : "https://safebrowsing.google.com/safebrowsing/report_phish/",
          "Red warning page in Chrome, Firefox, Safari and Android.",
        ),
      ],
    },
    {
      id: "microsoft-smartscreen",
      name: "Microsoft SmartScreen",
      role: "blocklist",
      match: {},
      channels: [form("https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site", "Warnings in Edge, Windows and Outlook.")],
    },
  ];
  if (category !== "malware") {
    list.push({
      id: "apwg",
      name: "APWG (Anti-Phishing Working Group)",
      role: "blocklist",
      match: {},
      channels: [email("reportphishing@apwg.org")],
      tip: "Shared with banks, browsers and law enforcement through the eCrimeX feed.",
    });
  }
  return list;
}

/** Registrar-specific forms. The abuse e-mail itself always comes live from RDAP. */
export const REGISTRAR_FORMS: Array<{ name: RegExp; channels: Channel[]; tip?: string }> = [
  { name: /cloudflare/i, channels: [form("https://abuse.cloudflare.com/registrar_whois")] },
  { name: /porkbun/i, channels: [form("https://porkbun.com/abuse")] },
  { name: /hostinger/i, channels: [form("https://www.hostinger.com/report-abuse")] },
  { name: /gname/i, channels: [form("https://www.gname.com/abuse")] },
];

/** Country authorities. Optional: add with --country. */
export const AUTHORITIES: Record<string, Provider[]> = {
  TR: [
    {
      id: "usom",
      name: "USOM (Ulusal Siber Olaylara Müdahale Merkezi)",
      role: "authority",
      match: {},
      channels: [form("https://www.usom.gov.tr/bildirim")],
      tip: "USOM's list is used by Turkish ISPs to block access nationwide. If you lost money, call your bank first, then file a complaint with the prosecutor's office or e-Devlet.",
    },
  ],
  GB: [
    {
      id: "ncsc-sers",
      name: "UK NCSC Suspicious Email Reporting Service",
      role: "authority",
      match: {},
      channels: [email("report@phishing.gov.uk"), form("https://www.gov.uk/report-suspicious-emails-websites-phishing")],
      tip: "Scam texts: forward to 7726 (free).",
    },
  ],
  US: [
    {
      id: "ftc",
      name: "US FTC ReportFraud",
      role: "authority",
      match: {},
      channels: [form("https://reportfraud.ftc.gov")],
      tip: "Losses: also file at https://complaint.ic3.gov. Scam texts: forward to 7726.",
    },
  ],
};

/** Mailbox providers used to send the scam or to receive replies (e-mail reports). */
export const MAIL_PROVIDERS: Array<{ domains: RegExp; provider: Provider }> = [
  {
    domains: /^(gmail|googlemail)\.com$/i,
    provider: {
      id: "gmail",
      name: "Gmail",
      role: "mail",
      match: {},
      channels: [form("https://support.google.com/mail/contact/abuse")],
    },
  },
];

function endsWith(value: string, suffix: string): boolean {
  const v = value.toLowerCase().replace(/\.$/, "");
  return v === suffix || v.endsWith(`.${suffix}`);
}

/** Every provider that serves this host, each with the evidence that matched. */
export function matchProviders(info: HostInfo): Array<{ provider: Provider; why: string[] }> {
  let out: Array<{ provider: Provider; why: string[]; asnOnly: boolean }> = [];
  for (const provider of PROVIDERS) {
    const m = provider.match;
    const why: string[] = [];
    const suffix = m.hostSuffix?.find((s) => endsWith(info.host, s));
    if (suffix) why.push(`hostname is under ${suffix}`);
    const cname = info.cnames.find((c) => m.cnameSuffix?.some((s) => endsWith(c, s)));
    if (cname) why.push(`DNS CNAME points to ${cname}`);
    const ns = info.nameservers.find((n) => m.nsSuffix?.some((s) => endsWith(n, s)));
    if (ns) why.push(`nameserver ${ns}`);
    const ip = info.ips.find((i) => m.ipPrefix?.some((p) => i.startsWith(p)));
    if (ip) why.push(`IP ${ip} belongs to ${provider.name}`);
    for (const [name, re] of m.header ?? []) {
      const v = info.headers[name];
      if (v && re.test(v)) why.push(`HTTP header ${name}: ${v}`);
    }
    const asnOnly = why.length === 0;
    if (info.asn && m.asn?.includes(info.asn.number)) why.push(`IP ${info.ips[0]} is announced by AS${info.asn.number} (${info.asn.name})`);
    if (why.length) out.push({ provider, why, asnOnly });
  }
  const ids = new Set(out.map((o) => o.provider.id));
  // A platform recognised by name/CNAME/header (e.g. Vercel) often runs on a cloud ASN (AWS);
  // the platform is who acts, so drop cloud matches that rest on the ASN alone. Cloudflare stays: its proxy is a real party.
  if (out.some((o) => !o.asnOnly && (o.provider.role === "host" || o.provider.role === "platform"))) {
    out = out.filter((o) => !o.asnOnly || o.provider.id === "cloudflare");
  }
  if (ids.has("cloudflare-pages")) out = out.filter((o) => o.provider.id !== "cloudflare" && o.provider.id !== "cloudflare-dns");
  if (ids.has("cloudflare")) out = out.filter((o) => o.provider.id !== "cloudflare-dns");
  return out.map(({ provider, why }) => ({ provider, why }));
}
