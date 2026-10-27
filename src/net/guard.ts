import type { LookupAddress, LookupOptions } from "node:dns";
import { isIP } from "node:net";
import { Agent } from "undici";
import { resolveHost } from "./dns.ts";
import { isPrivateIp } from "./ip.ts";

type LookupCallback = (err: Error | null, address: string | LookupAddress[], family?: number) => void;

/**
 * Resolve through our public resolvers and refuse private addresses at connect time.
 * Checking before fetch() is not enough: the name could resolve differently a moment later (DNS rebinding).
 */
function guardedLookup(hostname: string, options: LookupOptions, callback: LookupCallback): void {
  const host = hostname.replace(/^\[|\]$/g, "");
  const pending = isIP(host) ? Promise.resolve([host]) : resolveHost(host).then((r) => r.ips);
  pending
    .then((ips) => {
      if (!ips.length) return callback(Object.assign(new Error(`ENOTFOUND ${hostname}`), { code: "ENOTFOUND" }), "");
      if (ips.some(isPrivateIp)) return callback(new Error("refusing to connect to a private address"), "");
      const list = ips.map((address) => ({ address, family: isIP(address) }));
      if (options.all) return callback(null, list);
      callback(null, list[0]!.address, list[0]!.family);
    })
    .catch((e: Error) => callback(e, ""));
}

let agent: Agent | undefined;

/** undici dispatcher for fetch() that never reaches internal networks. */
export function guardedDispatcher(): Agent {
  agent ??= new Agent({ connect: { lookup: guardedLookup as never, timeout: 8000 } });
  return agent;
}
