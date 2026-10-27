import { expect, test } from "bun:test";
import { parseEmail } from "../src/email.ts";

const RAW = [
  "Received: from mail.example.net (mail.example.net [10.0.0.5]) by mx.google.com",
  "Received: from sender.bad-host.example ([203.0.114.9]) by mail.example.net",
  "From: \"Garanti BBVA\" <guvenlik@garanti-destek.top>",
  "Reply-To: bonus.garanti@gmail.com",
  "Subject: Hesabiniz askiya alindi",
  "Date: Mon, 26 Oct 2026 10:00:00 +0300",
  "MIME-Version: 1.0",
  "Content-Type: text/html; charset=utf-8",
  "",
  '<p>Hemen <a href="https://garanti-giris.top/login?u=1">giris yapin</a></p>',
].join("\r\n");

test("parses sender, links and the originating IP", async () => {
  const mail = await parseEmail(RAW);
  expect(mail.from).toBe("guvenlik@garanti-destek.top");
  expect(mail.replyTo).toBe("bonus.garanti@gmail.com");
  expect(mail.urls).toEqual(["https://garanti-giris.top/login?u=1"]);
  expect(mail.senderIps).toEqual(["203.0.114.9"]);
});
