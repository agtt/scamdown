import { expect, test } from "bun:test";
import { defang, extractFromText, refang } from "../src/extract.ts";

test("refang undoes common defanging", () => {
  expect(refang("hxxps://evil[.]com/a")).toBe("https://evil.com/a");
  expect(refang("evil(.)co[.]uk")).toBe("evil.co.uk");
  expect(defang("https://evil.com")).toBe("hxxps://evil[.]com");
});

test("finds scheme and bare links in an SMS", () => {
  const sms =
    "PTT: Gonderiniz adres eksikligi nedeniyle bekletilmektedir. Odeme icin: ptt-kargo-takip.xyz/odeme?id=88 " +
    "veya https://bit.ly/3abcDEF. Destek: yardim@ptt-destek.com +90 555 123 45 67";
  const out = extractFromText(sms);
  expect(out.urls).toEqual(["https://bit.ly/3abcDEF", "http://ptt-kargo-takip.xyz/odeme?id=88"]);
  expect(out.emails).toEqual(["yardim@ptt-destek.com"]);
  expect(out.phones).toEqual(["+905551234567"]);
});

test("ignores file names, versions and big legit sites", () => {
  const out = extractFromText("see report.pdf v1.2.3 at https://www.google.com and https://sites.google.com/view/fake-bank");
  expect(out.urls).toEqual(["https://sites.google.com/view/fake-bank"]);
});

test("trims trailing punctuation", () => {
  expect(extractFromText("Go to (https://evil.example.com/login).").urls).toEqual(["https://evil.example.com/login"]);
});
