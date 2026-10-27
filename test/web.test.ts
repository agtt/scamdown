import { expect, test } from "bun:test";
import { rateLimit, signPlan, verifyPlan } from "../src/web/guard.ts";
import { handle } from "../src/web/handler.ts";

test("plan tokens verify, and tampering or expiry is rejected", () => {
  const token = signPlan(["https://a.example/"]);
  expect(verifyPlan(token)).toEqual(["https://a.example/"]);
  const [payload, sig] = token.split(".");
  const forged = Buffer.from(JSON.stringify({ u: ["https://b.example/"], e: 9e9 })).toString("base64url");
  expect(verifyPlan(`${forged}.${sig}`)).toBeNull();
  expect(verifyPlan(`${payload}.AAAA`)).toBeNull();
  expect(verifyPlan(signPlan(["https://a.example/"], -1))).toBeNull();
  expect(verifyPlan("garbage")).toBeNull();
});

test("rate limit blocks after the limit", async () => {
  const id = `test-${Math.random()}`;
  for (let i = 0; i < 3; i++) expect(await rateLimit("t", id, 3, 60)).toBe(0);
  expect(await rateLimit("t", id, 3, 60)).toBeGreaterThan(0);
});

const post = (path: string, body: unknown, ip = "203.0.113.7") =>
  handle(new Request(`http://localhost${path}`, { method: "POST", headers: { "content-type": "application/json", "x-real-ip": ip }, body: JSON.stringify(body) }));

test("Netcraft relay needs a plan token covering the URLs", async () => {
  const res = await post("/api/netcraft", { urls: ["https://evil.example/"] });
  expect(res.status).toBe(403);
  const other = signPlan(["https://other.example/"]);
  expect((await post("/api/netcraft", { token: other, urls: ["https://evil.example/"] })).status).toBe(403);
});

test("private addresses are not accepted as links", async () => {
  const res = await post("/api/plan", { urls: ["http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data"] });
  expect(res.status).toBe(400);
});
