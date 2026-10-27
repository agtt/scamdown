import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CONFIG_DIR } from "./config.ts";

export interface HistoryEntry {
  url: string;
  target: string;
  channel: string;
  at: string;
  ok: boolean;
  detail?: string;
}

const FILE = join(CONFIG_DIR, "history.json");
/** Abuse desks ignore repeat senders; wait this long before reporting the same URL to the same place. */
export const REPEAT_AFTER_DAYS = 3;

export async function readHistory(): Promise<HistoryEntry[]> {
  try {
    return JSON.parse(await readFile(FILE, "utf8")) as HistoryEntry[];
  } catch {
    return [];
  }
}

export async function appendHistory(entries: HistoryEntry[]): Promise<void> {
  if (!entries.length) return;
  const all = [...(await readHistory()), ...entries];
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(FILE, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
}

export function recentlySent(history: HistoryEntry[], url: string, target: string, channel: string): HistoryEntry | undefined {
  const cutoff = Date.now() - REPEAT_AFTER_DAYS * 86_400_000;
  return history.find((h) => h.ok && h.url === url && h.target === target && h.channel === channel && Date.parse(h.at) > cutoff);
}
