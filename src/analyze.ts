import { parse } from "tldts";
import { isNoise } from "./extract.ts";
import { asnOf, nameservers, resolveHost } from "./net/dns.ts";
import { lookupDomain, lookupIp } from "./net/rdap.ts";
import { trace, type TraceOptions } from "./net/trace.ts";
import { AUTHORITIES, blocklists, matchProviders, REGISTRAR_FORMS, SHARED_DOMAINS, type Provider } from "./providers.ts";
import type { Category, DomainInfo, HostInfo, NetworkInfo, Target, UrlAnalysis } from "./types.ts";

export interface AnalyzeOptions extends TraceOptions {}

/** Resolve, trace and look up everything needed to decide where one URL should be reported. */
export async function analyzeUrl(url: string, opts: AnalyzeOptions = {}): Promise<UrlAnalysis> {
  const hops = await trace(url, opts);
  const warnings: string[] = [];

  const hostHeaders = new Map<string, Record<string, string>>();
  for (const hop of hops) {
    const host = new URL(hop.url).hostname.toLowerCase();
    hostHeaders.set(host, { ...hostHeaders.get(host), ...hop.headers });
  }
  // Skip big legitimate redirectors in the middle (google.com/url, l.facebook.com, ...).
  const hosts = [...hostHeaders.keys()].filter((h, i) => i === 0 || !isNoise(`http://${h}/`));

  const hostInfos: HostInfo[] = await Promise.all(
    hosts.map(async (host): Promise<HostInfo> => {
      const domain = parse(host).domain ?? null;
      const [resolved, ns] = await Promise.all([resolveHost(host), domain ? nameservers(domain) : []]);
      const asn = resolved.ips[0] ? await asnOf(resolved.ips[0]) : undefined;
      return { host, domain, ips: resolved.ips, cnames: resolved.cnames, nameservers: ns, asn, headers: hostHeaders.get(host) ?? {} };
    }),
  );

  const domainNames = [...new Set(hostInfos.map((h) => h.domain).filter((d): d is string => !!d))];
  const domains: DomainInfo[] = await Promise.all(domainNames.map(lookupDomain));
  const ips = [...new Set(hostInfos.map((h) => h.ips.find((ip) => !ip.includes(":")) ?? h.ips[0]).filter((i): i is string => !!i))];
  const networks: NetworkInfo[] = await Promise.all(ips.map(lookupIp));

  const last = hops.at(-1);
  const alive = !!last && last.status !== undefined && last.status < 500 && last.status !== 404 && last.status !== 410;
  if (hostInfos[0] && hostInfos[0].ips.length === 0) warnings.push(`${hostInfos[0].host} does not resolve: it may already be down.`);
  for (const d of domains) {
    if (d.onHold) warnings.push(`${d.domain} is on registry hold (${d.statuses.join(", ")}): already suspended.`);
    if (d.ageDays !== undefined && d.ageDays <= 30) warnings.push(`${d.domain} was registered ${d.ageDays} day(s) ago.`);
  }
  if (last?.error) warnings.push(`Fetching ${last.url} failed: ${last.error}`);

  return {
    url,
    finalUrl: last?.url ?? url,
    hops,
    hosts: hostInfos,
    domains,
    networks,
    alive,
    checkedAt: new Date().toISOString(),
    warnings,
  };
}

const PRIORITY: Record<Target["role"], number> = {
  blocklist: 1,
  host: 2,
  platform: 2,
  shortener: 2,
  registrar: 3,
  cdn: 3,
  mail: 3,
  network: 4,
  dns: 5,
  authority: 6,
};

function addTarget(map: Map<string, Target>, t: Omit<Target, "priority" | "urls">, url: string): void {
  const existing = map.get(t.id);
  if (existing) {
    if (!existing.urls.includes(url)) existing.urls.push(url);
    for (const w of t.why) if (!existing.why.includes(w)) existing.why.push(w);
    return;
  }
  map.set(t.id, { ...t, priority: PRIORITY[t.role], urls: [url] });
}

function fromProvider(p: Provider, why: string[]): Omit<Target, "priority" | "urls"> {
  return { id: p.id, name: p.name, role: p.role, why, channels: p.channels, tip: p.tip };
}

/**
 * Turn analyses into a de-duplicated list of places to report, each with the URLs that concern it.
 * One e-mail per destination is friendlier to abuse desks than one per URL.
 */
export function planTargets(analyses: UrlAnalysis[], opts: { category: Category; country?: string }): Target[] {
  const map = new Map<string, Target>();
  const seenEmails = new Set<string>();

  for (const a of analyses) {
    // The name no longer resolves: nothing is reachable, so there is nobody to bother.
    if (!a.hosts[0]?.ips.length) continue;
    for (const p of blocklists(opts.category)) addTarget(map, fromProvider(p, ["reports reach browser and mail blocklists"]), a.url);

    let hostedByKnown = false;
    for (const host of a.hosts) {
      for (const { provider, why } of matchProviders(host)) {
        if (provider.role === "host" || provider.role === "platform") hostedByKnown = true;
        addTarget(map, fromProvider(provider, why.map((w) => `${host.host}: ${w}`)), a.url);
        for (const c of provider.channels) if (c.kind === "email") seenEmails.add(c.to.toLowerCase());
      }
    }

    for (const d of a.domains) {
      // Shared platform domains (vercel.app, github.io, ...) are not the scammer's registration.
      if (SHARED_DOMAINS.has(d.domain)) continue;
      if (a.hosts.some((h) => h.domain === d.domain && matchProviders(h).some((m) => m.why.some((w) => w.startsWith("hostname is under"))))) continue;
      const r = d.registrar;
      if (!r) continue;
      const extra = REGISTRAR_FORMS.find((f) => f.name.test(r.name));
      const channels = [...(extra?.channels ?? []), ...(r.email ? [{ kind: "email" as const, to: r.email }] : [])];
      if (!channels.length) continue;
      const age = d.ageDays !== undefined ? `, registered ${d.ageDays} day(s) ago` : "";
      addTarget(
        map,
        {
          id: `registrar:${r.ianaId ?? r.name.toLowerCase()}`,
          name: `${r.name} (registrar)`,
          role: "registrar",
          why: [`${d.domain} is registered with ${r.name}${r.ianaId ? ` (IANA ${r.ianaId})` : ""}${age}`],
          channels,
          tip: "Registrars can suspend the whole domain, which also kills every subdomain and the mail setup.",
        },
        a.url,
      );
      if (r.email) seenEmails.add(r.email.toLowerCase());
    }

    // The network owner is the fallback when no known platform claims the site (VPS, shared hosting).
    for (const n of a.networks) {
      const to = n.abuse?.email?.toLowerCase();
      if (!to || seenEmails.has(to)) continue;
      const host = a.hosts.find((h) => h.ips.includes(n.ip));
      const cdnOnly = host && matchProviders(host).some((m) => m.provider.role === "cdn");
      if (hostedByKnown || cdnOnly || (host?.domain && SHARED_DOMAINS.has(host.domain))) continue;
      addTarget(
        map,
        {
          id: `network:${to}`,
          name: `${n.name ?? "Network owner"} (IP ${n.ip}${host?.asn ? `, AS${host.asn.number} ${host.asn.name}` : ""})`,
          role: "network",
          why: [`${host?.host ?? a.url} resolves to ${n.ip}, managed by ${n.name ?? to}`],
          channels: [{ kind: "email", to }],
        },
        a.url,
      );
    }

    for (const p of AUTHORITIES[opts.country?.toUpperCase() ?? ""] ?? []) addTarget(map, fromProvider(p, [`national reporting for ${opts.country}`]), a.url);
  }
  return [...map.values()].sort((x, y) => x.priority - y.priority);
}
