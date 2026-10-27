import { expect, test } from "bun:test";
import { parseEmail } from "../src/email.ts";

const RAW = [
  "Received: from mail.example.net (mail.example.net [10.0.0.5]) by mx.google.com",
  "Received: from sender.bad-host.example ([203.0.114.9]) by mail.example.net",
  "From: \"Chase Security\" <alerts@chase-secure.top>",
  "Reply-To: chase.refunds@gmail.com",
  "Subject: Your account has been suspended",
  "Date: Mon, 26 Oct 2026 10:00:00 -0400",
  "MIME-Version: 1.0",
  "Content-Type: text/html; charset=utf-8",
  "",
  '<p>Please <a href="https://chase-login.top/verify?u=1">verify your account</a> now.</p>',
].join("\r\n");

test("parses sender, links and the originating IP", async () => {
  const mail = await parseEmail(RAW);
  expect(mail.from).toBe("alerts@chase-secure.top");
  expect(mail.replyTo).toBe("chase.refunds@gmail.com");
  expect(mail.urls).toEqual(["https://chase-login.top/verify?u=1"]);
  expect(mail.senderIps).toEqual(["203.0.114.9"]);
});
