import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dir, "../public/locales");
const keys = (file: string) => Object.keys(JSON.parse(readFileSync(join(dir, file), "utf8")));
const en = keys("en.json");

for (const file of readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "en.json")) {
  test(`${file} has exactly the English keys`, () => {
    expect(keys(file)).toEqual(en);
  });
}

test("every locale is listed in the page", () => {
  const app = readFileSync(join(dir, "../app.js"), "utf8");
  for (const file of readdirSync(dir)) expect(app).toContain(`${file.replace(".json", "")}: "`);
});
