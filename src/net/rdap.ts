import type { Contact, DomainInfo, NetworkInfo } from "../types.ts";
import { cached } from "./cache.ts";

// rdap.org redirects to the authoritative registry / RIR server (IANA bootstrap).
const RDAP = "https://rdap.org";

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
  publicIds?: Array<{ type: string; identifier: string }>;
  entities?: RdapEntity[];
  handle?: string;
}

interface RdapDoc {
  entities?: RdapEntity[];
  events?: Array<{ eventAction: string; eventDate: string }>;
  status?: string[];
  links?: Array<{ rel?: string; href?: string; type?: string }>;
  name?: string;
  handle?: string;
  country?: string;
}

async function getJson(url: string): Promise<RdapDoc | null> {
  try {
    const res = await fetch(url, {
      headers: { accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return (await res.json()) as RdapDoc;
  } catch {
    return null;
  }
}

function vcard(entity: RdapEntity, field: string): string | undefined {
  const row = entity.vcardArray?.[1]?.find((r) => r[0] === field);
  const value = row?.[3];
  const raw = typeof value === "string" ? value : Array.isArray(value) ? value.filter(Boolean).join(" ") : "";
  // RDAP data for an IP block can be written by whoever holds it, i.e. possibly the scammer.
  const text = raw.replace(/^(mailto|tel):/i, "").replace(/[\p{Cc}\p{Cf}]/gu, "").trim().slice(0, 120);
  if (field === "email") return EMAIL.test(text) ? text.toLowerCase() : undefined;
  return text || undefined;
}

const EMAIL = /^[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/i;

function walk(entities: RdapEntity[] | undefined, visit: (e: RdapEntity) => void): void {
  for (const e of entities ?? []) {
    visit(e);
    walk(e.entities, visit);
  }
}

function findRole(entities: RdapEntity[] | undefined, role: string): RdapEntity | undefined {
  let hit: RdapEntity | undefined;
  walk(entities, (e) => {
    if (!hit && e.roles?.includes(role)) hit = e;
  });
  return hit;
}

function abuseOf(entities: RdapEntity[] | undefined): Contact | undefined {
  const e = findRole(entities, "abuse");
  if (!e) return undefined;
  const email = vcard(e, "email");
  if (!email) return undefined;
  return { name: vcard(e, "fn") ?? "Abuse", email, phone: vcard(e, "tel") };
}

function registrarOf(doc: RdapDoc): Contact | undefined {
  const reg = findRole(doc.entities, "registrar");
  if (!reg) return undefined;
  const abuse = abuseOf(reg.entities);
  return {
    name: vcard(reg, "fn") ?? reg.handle ?? "Unknown registrar",
    ianaId: reg.publicIds?.find((p) => /iana/i.test(p.type))?.identifier,
    email: abuse?.email,
    phone: abuse?.phone,
  };
}

const HOLD = /(server|client)\s?hold|inactive|redemption|pending\s?delete/i;

export function lookupDomain(domain: string): Promise<DomainInfo> {
  return cached(`rdap-domain:${domain}`, 10 * 60_000, () => fetchDomain(domain));
}

export function lookupIp(ip: string): Promise<NetworkInfo> {
  return cached(`rdap-ip:${ip}`, 60 * 60_000, () => fetchIp(ip));
}

async function fetchDomain(domain: string): Promise<DomainInfo> {
  const info: DomainInfo = { domain, statuses: [], onHold: false };
  let doc = await getJson(`${RDAP}/domain/${encodeURIComponent(domain)}`);
  if (!doc) return info;
  info.statuses = doc.status ?? [];
  info.onHold = info.statuses.some((s) => HOLD.test(s));
  const reg = doc.events?.find((e) => e.eventAction === "registration")?.eventDate;
  if (reg) {
    info.registeredAt = reg;
    info.ageDays = Math.floor((Date.now() - Date.parse(reg)) / 86_400_000);
  }
  info.registrar = registrarOf(doc);

  // Thin registries (.com/.net) carry the abuse contact; others point to the registrar's RDAP.
  if (!info.registrar?.email) {
    const related = doc.links?.find((l) => l.rel === "related" && l.href && /rdap/i.test(l.type ?? l.href));
    if (related?.href) {
      doc = await getJson(related.href);
      const more = doc ? registrarOf(doc) : undefined;
      if (more?.email) info.registrar = { ...info.registrar, ...more, name: info.registrar?.name ?? more.name };
    }
  }
  return info;
}

async function fetchIp(ip: string): Promise<NetworkInfo> {
  const doc = await getJson(`${RDAP}/ip/${encodeURIComponent(ip)}`);
  if (!doc) return { ip };
  return { ip, name: doc.name ?? doc.handle, country: doc.country, abuse: abuseOf(doc.entities) };
}
