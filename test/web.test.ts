import { expect, test } from "bun:test";
import { rateLimit, signPlan, verifyPlan } from "../src/web/guard.ts";
import { handle } from "../src/web/handler.ts";
import { isPrivateIp } from "../src/net/ip.ts";

test("plan tokens verify, and tampering or expiry is rejected", () => {
  const token = signPlan(["https://a.example/"], { netcraft: ["https://a.example/"] });
  expect(verifyPlan(token)).toEqual({ urls: ["https://a.example/"], targets: { netcraft: ["https://a.example/"] } });
  const [payload, sig] = token.split(".");
  const forged = Buffer.from(JSON.stringify({ u: ["https://b.example/"], e: 9e9 })).toString("base64url");
  expect(verifyPlan(`${forged}.${sig}`)).toBeNull();
  expect(verifyPlan(`${payload}.AAAA`)).toBeNull();
  expect(verifyPlan(signPlan(["https://a.example/"], {}, -1))).toBeNull();
  expect(verifyPlan("garbage")).toBeNull();
});

test("IPv6 spellings of private addresses are caught", () => {
  for (const ip of ["::1", "::", "::ffff:127.0.0.1", "::ffff:7f00:1", "::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:c0a8:101::1", "fd00::1", "fe80::1%en0", "2001:db8::1"]) {
    expect(isPrivateIp(ip)).toBe(true);
  }
  for (const ip of ["2606:4700::6810:84e5", "2a00:1450:4009:80b::200e", "::ffff:8.8.8.8", "8.8.8.8"]) expect(isPrivateIp(ip)).toBe(false);
});

test("rate limit blocks after the limit", async () => {
  const id = `test-${Math.random()}`;
  for (let i = 0; i < 3; i++) expect(await rateLimit("t", id, 3, 60)).toBe(0);
  expect(await rateLimit("t", id, 3, 60)).toBeGreaterThan(0);
});

const post = (path: string, body: unknown, ip = "203.0.113.7") =>
  handle(new Request(`http://localhost${path}`, { method: "POST", headers: { "content-type": "application/json", "x-real-ip": ip }, body: JSON.stringify(body) }));

test("Netcraft and counters only act on targets in a signed plan", async () => {
  expect((await post("/api/netcraft", {})).status).toBe(403);
  const noNetcraft = signPlan(["https://other.example/"], { "registrar-1": ["https://other.example/"] });
  expect((await post("/api/netcraft", { token: noNetcraft })).status).toBe(403);
  expect((await post("/api/sent", { token: noNetcraft, target: "made-up" })).status).toBe(403);
  expect((await post("/api/sent", { token: noNetcraft, target: "registrar-1" })).status).toBe(200);
});

test("private addresses are not accepted as links", async () => {
  const res = await post("/api/plan", { urls: ["http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data"] });
  expect(res.status).toBe(400);
});
