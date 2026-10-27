import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { Asn } from "../types.ts";
import { reverseV4 } from "./ip.ts";

// Public resolvers: ISP or corporate DNS may sinkhole scam domains and hide the real host.
const resolver = new Resolver({ timeout: 4000, tries: 2 });
resolver.setServers(["1.1.1.1", "8.8.8.8", "9.9.9.9"]);

async function safe<T>(p: Promise<T>, fallback: T): Promise<T> {
  try {
    return await p;
  } catch {
    return fallback;
  }
}

export interface Resolved {
  ips: string[];
  cnames: string[];
  /** true when the name does not exist at all (NXDOMAIN). */
  missing: boolean;
}

export async function resolveHost(host: string): Promise<Resolved> {
  if (isIP(host)) return { ips: [host], cnames: [], missing: false };
  const cnames: string[] = [];
  let name = host;
  for (let i = 0; i < 6; i++) {
    const next = await safe(resolver.resolveCname(name), [] as string[]);
    if (!next[0]) break;
    name = next[0].toLowerCase();
    cnames.push(name);
  }
  let missing = false;
  const v4 = await resolver.resolve4(host).catch((e: NodeJS.ErrnoException) => {
    if (e.code === "ENOTFOUND") missing = true;
    return [] as string[];
  });
  const v6 = await safe(resolver.resolve6(host), [] as string[]);
  return { ips: [...v4, ...v6], cnames, missing: missing && v6.length === 0 && cnames.length === 0 };
}

export async function nameservers(domain: string): Promise<string[]> {
  return (await safe(resolver.resolveNs(domain), [] as string[])).map((n) => n.toLowerCase());
}

/** IP -> origin ASN using Team Cymru's DNS service (free, no key). IPv4 only. */
export async function asnOf(ip: string): Promise<Asn | undefined> {
  if (isIP(ip) !== 4) return undefined;
  const origin = await safe(resolver.resolveTxt(`${reverseV4(ip)}.origin.asn.cymru.com`), [] as string[][]);
  const fields = origin[0]?.join("").split("|").map((s) => s.trim());
  const number = Number(fields?.[0]?.split(" ")[0]);
  if (!fields || !Number.isFinite(number) || number === 0) return undefined;
  const desc = await safe(resolver.resolveTxt(`AS${number}.asn.cymru.com`), [] as string[][]);
  const name = desc[0]?.join("").split("|").at(-1)?.trim() ?? `AS${number}`;
  return { number, name, prefix: fields[1] ?? "", country: fields[2] ?? "" };
}
