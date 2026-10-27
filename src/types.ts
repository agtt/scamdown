export type Category = "phishing" | "scam" | "malware";

export type Role =
  | "blocklist"
  | "host"
  | "cdn"
  | "dns"
  | "registrar"
  | "network"
  | "shortener"
  | "platform"
  | "mail"
  | "authority";

export type ApiName = "netcraft" | "cloudflare";

export type Channel =
  | { kind: "email"; to: string }
  | { kind: "form"; url: string; note?: string }
  | { kind: "api"; api: ApiName };

/** Somewhere a report can be sent, with the reasons it applies to these URLs. */
export interface Target {
  id: string;
  name: string;
  role: Role;
  why: string[];
  channels: Channel[];
  /** Lower goes first. Blocklists protect people fastest, so they lead. */
  priority: number;
  urls: string[];
  tip?: string;
}

export interface Hop {
  url: string;
  status?: number;
  error?: string;
  headers: Record<string, string>;
  title?: string;
  via?: "start" | "http" | "meta" | "js";
}

export interface HostInfo {
  host: string;
  domain: string | null;
  ips: string[];
  cnames: string[];
  nameservers: string[];
  asn?: Asn;
  /** Response headers of the hops this host served (lower-cased keys). */
  headers: Record<string, string>;
}

export interface Asn {
  number: number;
  name: string;
  prefix: string;
  country: string;
}

export interface Contact {
  name: string;
  email?: string;
  phone?: string;
  ianaId?: string;
}

export interface DomainInfo {
  domain: string;
  registrar?: Contact;
  registeredAt?: string;
  ageDays?: number;
  statuses: string[];
  /** The registry put the domain on hold: it is already suspended. */
  onHold: boolean;
}

export interface NetworkInfo {
  ip: string;
  name?: string;
  country?: string;
  abuse?: Contact;
}

export interface UrlAnalysis {
  url: string;
  finalUrl: string;
  hops: Hop[];
  hosts: HostInfo[];
  domains: DomainInfo[];
  networks: NetworkInfo[];
  /** false when the site no longer resolves or answers: maybe already taken down. */
  alive: boolean;
  checkedAt: string;
  warnings: string[];
}

export interface ScreenshotFile {
  filename: string;
  mime: string;
  data: Uint8Array;
}

/** What the reporter knows beyond the URLs themselves. */
export interface Evidence {
  category: Category;
  brand?: string;
  /** How it reached victims, e.g. "SMS from +90 555 000 00 00 on 2026-10-26". */
  delivery?: string;
  notes?: string;
  screenshot?: ScreenshotFile;
  /** Raw RFC 822 message when the report is about a phishing e-mail. */
  rawEmail?: string;
  /** Public scan links (urlscan.io) that abuse desks can open safely. */
  scans?: string[];
}

export interface Reporter {
  name: string;
  email: string;
}

export interface Report {
  target: Target;
  channel: Channel;
  subject: string;
  body: string;
  urls: string[];
}

export interface Extracted {
  urls: string[];
  emails: string[];
  phones: string[];
  brand?: string;
  kind?: string;
  summary?: string;
}
