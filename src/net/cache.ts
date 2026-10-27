const store = new Map<string, { at: number; value: Promise<unknown> }>();
const MAX = 2000;

/**
 * Memoise a lookup for `ttlMs`. The promise itself is cached, so concurrent callers
 * (several URLs on one domain, prefetch + real use) share one network request.
 */
export function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const hit = store.get(key);
  if (hit && Date.now() - hit.at < ttlMs) return hit.value as Promise<T>;
  const value = fn();
  store.set(key, { at: Date.now(), value });
  value.catch(() => store.delete(key));
  if (store.size > MAX) store.delete(store.keys().next().value as string);
  return value;
}
