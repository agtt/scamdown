/**
 * Counters shared by every serverless instance: Upstash Redis over its REST API when
 * UPSTASH_REDIS_REST_URL / _TOKEN are set (the Vercel Marketplace integration sets them),
 * otherwise memory, which is fine for `scamdown web` on one machine.
 */
export interface Store {
  /** Increment and return the new value; the key expires `ttlSec` after it was created. */
  incr(key: string, ttlSec: number): Promise<number>;
  get(keys: string[]): Promise<number[]>;
}

class MemoryStore implements Store {
  private data = new Map<string, { n: number; until: number }>();

  async incr(key: string, ttlSec: number): Promise<number> {
    const now = Date.now();
    const cur = this.data.get(key);
    const entry = cur && cur.until > now ? cur : { n: 0, until: now + ttlSec * 1000 };
    entry.n++;
    this.data.set(key, entry);
    if (this.data.size > 20000) {
      for (const [k, v] of this.data) if (v.until <= now) this.data.delete(k);
    }
    return entry.n;
  }

  async get(keys: string[]): Promise<number[]> {
    const now = Date.now();
    return keys.map((k) => {
      const v = this.data.get(k);
      return v && v.until > now ? v.n : 0;
    });
  }
}

class UpstashStore implements Store {
  constructor(private url: string, private token: string) {}

  private async pipeline(commands: Array<Array<string | number>>): Promise<Array<{ result: unknown }>> {
    const res = await fetch(`${this.url}/pipeline`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify(commands),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error(`redis ${res.status}`);
    return (await res.json()) as Array<{ result: unknown }>;
  }

  async incr(key: string, ttlSec: number): Promise<number> {
    const [n] = await this.pipeline([["INCR", key], ["EXPIRE", key, ttlSec, "NX"]]);
    return Number(n?.result ?? 0);
  }

  async get(keys: string[]): Promise<number[]> {
    if (!keys.length) return [];
    const [r] = await this.pipeline([["MGET", ...keys]]);
    return ((r?.result as Array<string | null>) ?? []).map((v) => Number(v ?? 0));
  }
}

let store: Store | undefined;

export function getStore(): Store {
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
  store ??= url && token ? new UpstashStore(url.replace(/\/$/, ""), token) : new MemoryStore();
  return store;
}
