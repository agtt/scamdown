import { isIP } from "node:net";

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((n, part) => (n << 8) + Number(part), 0) >>> 0;
}

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

/** "::ffff:7f00:1" -> [0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]. Handles "::" and a dotted IPv4 tail. */
function v6Groups(ip: string): number[] {
  let s = ip.toLowerCase().replace(/%.*$/, "");
  const tail = s.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (tail) {
    const n = v4ToInt(tail);
    s = s.slice(0, -tail.length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, rest] = s.split("::") as [string, string | undefined];
  const a = head ? head.split(":") : [];
  const b = rest ? rest.split(":") : [];
  const fill = rest === undefined ? [] : Array(8 - a.length - b.length).fill("0");
  return [...a, ...fill, ...b].map((g) => parseInt(g, 16));
}

const v4Of = (hi: number, lo: number) => `${hi >>> 8}.${hi & 255}.${lo >>> 8}.${lo & 255}`;

/** Private, loopback, link-local and other addresses a public scam site can never legitimately use. */
export function isPrivateIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) {
    const n = v4ToInt(ip);
    return V4_BLOCKED.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (v4ToInt(base) & mask);
    });
  }
  if (family === 6) {
    const g = v6Groups(ip);
    if (g.length !== 8 || g.some((x) => Number.isNaN(x))) return true;
    const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [number, number, number, number, number, number, number, number];
    // Forms that carry an IPv4 address: mapped ::ffff:0:0/96, compatible ::/96 (also :: and ::1), NAT64 64:ff9b::/96.
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && (g5 === 0 || g5 === 0xffff)) return isPrivateIp(v4Of(g6, g7));
    if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return isPrivateIp(v4Of(g6, g7));
    if (g0 === 0x2002) return isPrivateIp(v4Of(g1, g2)); // 6to4
    return (
      g0 === 0 || // everything else in ::/16, incl. ::ffff:0:0:0/96 translated forms
      (g0 === 0x64 && g1 === 0xff9b) || // local-use NAT64 64:ff9b:1::/48
      (g0 === 0x100 && g1 === 0 && g2 === 0 && g3 === 0) || // discard 100::/64
      (g0 === 0x2001 && g1 < 0x200) || // Teredo, benchmarking, ORCHID and other IETF special use in 2001::/23
      (g0 === 0x2001 && g1 === 0xdb8) || // documentation
      (g0 & 0xfe00) === 0xfc00 || // unique local fc00::/7
      (g0 & 0xffc0) === 0xfe80 || // link-local fe80::/10
      (g0 & 0xffc0) === 0xfec0 || // old site-local fec0::/10
      (g0 & 0xff00) === 0xff00 // multicast
    );
  }
  return true;
}

/** "1.2.3.4" -> "4.3.2.1" (for DNS-based lookups such as Team Cymru). */
export function reverseV4(ip: string): string {
  return ip.split(".").reverse().join(".");
}
