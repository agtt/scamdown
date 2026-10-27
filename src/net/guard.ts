import type { LookupAddress, LookupOptions } from "node:dns";
import { isIP } from "node:net";
import { Agent, buildConnector } from "undici";
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
const refused = () => new Error("refusing to connect to a private address");

/**
 * Node skips the lookup hook for IP literals, so the connected socket's address is checked as well.
 * That catches every path: literals, odd IPv6 spellings, and anything the lookup missed.
 */
const connector = (base: buildConnector.connector): buildConnector.connector => (opts, callback) => {
  const host = opts.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host) && isPrivateIp(host)) return void callback(refused(), null);
  base(opts, (err, socket) => {
    if (err || !socket) return callback(err ?? refused(), null);
    const remote = (socket as { remoteAddress?: string }).remoteAddress;
    if (!remote || isPrivateIp(remote)) {
      socket.destroy();
      return callback(refused(), null);
    }
    callback(null, socket);
  });
};

/** undici dispatcher for fetch() that never reaches internal networks. */
export function guardedDispatcher(): Agent {
  agent ??= new Agent({ connect: connector(buildConnector({ lookup: guardedLookup as never, timeout: 8000 })) });
  return agent;
}
