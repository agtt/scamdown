import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export interface Config {
  name?: string;
  email?: string;
  /** smtp://user:pass@host:587 or smtps://user:pass@host:465 */
  smtpUrl?: string;
  smtpFrom?: string;
  country?: string;
  urlscanKey?: string;
  cloudflareToken?: string;
  cloudflareAccountId?: string;
  anthropicKey?: string;
  visionModel?: string;
}

export const CONFIG_DIR = process.env.SCAMDOWN_HOME ?? join(homedir(), ".scamdown");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

const ENV: Record<keyof Config, string> = {
  name: "SCAMDOWN_NAME",
  email: "SCAMDOWN_EMAIL",
  smtpUrl: "SCAMDOWN_SMTP_URL",
  smtpFrom: "SCAMDOWN_SMTP_FROM",
  country: "SCAMDOWN_COUNTRY",
  urlscanKey: "URLSCAN_API_KEY",
  cloudflareToken: "CLOUDFLARE_API_TOKEN",
  cloudflareAccountId: "CLOUDFLARE_ACCOUNT_ID",
  anthropicKey: "ANTHROPIC_API_KEY",
  visionModel: "SCAMDOWN_VISION_MODEL",
};

/** Environment variables win over ~/.scamdown/config.json. */
export async function loadConfig(): Promise<Config> {
  let file: Config = {};
  try {
    file = JSON.parse(await readFile(CONFIG_FILE, "utf8")) as Config;
  } catch {
    // no config yet
  }
  const out: Config = { ...file };
  for (const [key, env] of Object.entries(ENV) as Array<[keyof Config, string]>) {
    const v = process.env[env];
    if (v) out[key] = v;
  }
  return out;
}

export async function saveConfig(config: Config): Promise<string> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await chmod(CONFIG_FILE, 0o600);
  return CONFIG_FILE;
}
