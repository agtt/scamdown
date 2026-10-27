import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { Asn } from "../types.ts";
import { cached } from "./cache.ts";
import { reverseV4 } from "./ip.ts";

// Public resolvers: ISP or corporate DNS may sinkhole scam domains and hide the real host.
const resolver = new Resolver({ timeout: 3000, tries: 2 });
resolver.setServers(["1.1.1.1", "8.8.8.8", "9.9.9.9"]);

const MINUTE = 60_000;

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

async function cnameChain(host: string): Promise<string[]> {
  const chain: string[] = [];
  let name = host;
  for (let i = 0; i < 6; i++) {
    const next = await safe(resolver.resolveCname(name), [] as string[]);
    if (!next[0]) break;
    name = next[0].toLowerCase();
    chain.push(name);
  }
  return chain;
}

export function resolveHost(host: string): Promise<Resolved> {
  if (isIP(host)) return Promise.resolve({ ips: [host], cnames: [], missing: false });
  return cached(`dns:${host}`, 5 * MINUTE, async () => {
    let missing = false;
    const [cnames, v4, v6] = await Promise.all([
      cnameChain(host),
      resolver.resolve4(host).catch((e: NodeJS.ErrnoException) => {
        if (e.code === "ENOTFOUND") missing = true;
        return [] as string[];
      }),
      safe(resolver.resolve6(host), [] as string[]),
    ]);
    return { ips: [...v4, ...v6], cnames, missing: missing && v6.length === 0 && cnames.length === 0 };
  });
}

export function nameservers(domain: string): Promise<string[]> {
  return cached(`ns:${domain}`, 30 * MINUTE, async () =>
    (await safe(resolver.resolveNs(domain), [] as string[])).map((n) => n.toLowerCase()),
  );
}

/** IP -> origin ASN using Team Cymru's DNS service (free, no key). IPv4 only. */
export function asnOf(ip: string): Promise<Asn | undefined> {
  if (isIP(ip) !== 4) return Promise.resolve(undefined);
  return cached(`asn:${ip}`, 60 * MINUTE, async () => {
    const origin = await safe(resolver.resolveTxt(`${reverseV4(ip)}.origin.asn.cymru.com`), [] as string[][]);
    const fields = origin[0]?.join("").split("|").map((s) => s.trim());
    const number = Number(fields?.[0]?.split(" ")[0]);
    if (!fields || !Number.isFinite(number) || number === 0) return undefined;
    const desc = await safe(resolver.resolveTxt(`AS${number}.asn.cymru.com`), [] as string[][]);
    const name = desc[0]?.join("").split("|").at(-1)?.trim() ?? `AS${number}`;
    return { number, name, prefix: fields[1] ?? "", country: fields[2] ?? "" };
  });
}
