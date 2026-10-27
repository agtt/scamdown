import { expect, test } from "bun:test";
import { planTargets } from "../src/analyze.ts";
import { composeReports } from "../src/compose.ts";
import { isPrivateIp } from "../src/net/ip.ts";
import { matchProviders } from "../src/providers.ts";
import { chooseChannel } from "../src/send/index.ts";
import type { HostInfo, UrlAnalysis } from "../src/types.ts";

const host = (over: Partial<HostInfo>): HostInfo => ({
  host: "x.example", domain: "example", ips: [], cnames: [], nameservers: [], headers: {}, ...over,
});

test("Vercel by CNAME and header beats the AWS ASN underneath", () => {
  const ids = matchProviders(
    host({
      host: "bank-login.com",
      cnames: ["cname.vercel-dns.com"],
      ips: ["76.76.21.21"],
      headers: { server: "Vercel" },
      asn: { number: 16509, name: "AMAZON-02", prefix: "", country: "US" },
    }),
  ).map((m) => m.provider.id);
  expect(ids).toEqual(["vercel"]);
});

test("Cloudflare proxy is recognised from cf-ray and ASN, DNS match folds into it", () => {
  const ids = matchProviders(
    host({ headers: { "cf-ray": "8abc-IST" }, nameservers: ["ada.ns.cloudflare.com"], asn: { number: 13335, name: "CLOUDFLARENET", prefix: "", country: "US" }, ips: ["104.21.1.1"] }),
  ).map((m) => m.provider.id);
  expect(ids).toEqual(["cloudflare"]);
});

const analysis: UrlAnalysis = {
  url: "https://ptt-odeme.xyz/",
  finalUrl: "https://ptt-odeme.xyz/",
  hops: [{ url: "https://ptt-odeme.xyz/", status: 200, headers: { "cf-ray": "1" }, title: "PTT Odeme" }],
  hosts: [host({ host: "ptt-odeme.xyz", domain: "ptt-odeme.xyz", ips: ["104.21.1.1"], headers: { "cf-ray": "1" } })],
  domains: [{ domain: "ptt-odeme.xyz", statuses: [], onHold: false, ageDays: 2, registeredAt: "2026-10-25T00:00:00Z", registrar: { name: "NameSilo, LLC", ianaId: "1479", email: "abuse@namesilo.com" } }],
  networks: [{ ip: "104.21.1.1", name: "CLOUDFLARENET", abuse: { name: "Abuse", email: "abuse@cloudflare.com" } }],
  alive: true,
  checkedAt: "2026-10-27T10:00:00Z",
  warnings: [],
};

test("plan covers blocklists, CDN and registrar; skips the CDN's network abuse", () => {
  const targets = planTargets([analysis], { category: "phishing", country: "TR" });
  const ids = targets.map((t) => t.id);
  expect(ids.slice(0, 4)).toEqual(["netcraft", "google-safebrowsing", "microsoft-smartscreen", "apwg"]);
  expect(ids).toContain("cloudflare");
  expect(ids).toContain("registrar:1479");
  expect(ids).toContain("usom");
  expect(ids.some((id) => id.startsWith("network:"))).toBe(false);
});

test("drafts carry the evidence and one channel is chosen per target", () => {
  const targets = planTargets([analysis], { category: "phishing" });
  const reports = composeReports(targets, [analysis], { category: "phishing", brand: "PTT", delivery: "SMS from +905551234567" }, { name: "A", email: "a@b.co" });
  const registrar = reports.find((r) => r.target.id === "registrar:1479");
  expect(registrar?.body).toContain("registered with NameSilo");
  expect(registrar?.body).toContain("SMS from +905551234567");
  expect(registrar?.subject).toBe("[Phishing] ptt-odeme.xyz impersonating PTT");
  const cf = targets.find((t) => t.id === "cloudflare")!;
  expect(chooseChannel(cf.channels, {})?.kind).toBe("form");
  expect(chooseChannel(cf.channels, { cloudflareToken: "t", cloudflareAccountId: "a" })?.kind).toBe("api");
});

test("private addresses are blocked", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00::1", "::ffff:10.0.0.1"]) expect(isPrivateIp(ip)).toBe(true);
  for (const ip of ["76.76.21.21", "104.21.1.1", "2606:4700::1"]) expect(isPrivateIp(ip)).toBe(false);
});
