const UA = "scamdown (+https://github.com/agtt/scamdown)";

async function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": UA, ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    // keep text
  }
  if (!res.ok) throw new Error(`${res.status} ${typeof data === "string" ? data.slice(0, 300) : JSON.stringify(data).slice(0, 300)}`);
  return data;
}

/** Netcraft's public report API. No key; the reporter e-mail gets status updates. */
export async function netcraftUrls(email: string, urls: string[], reason: string): Promise<string> {
  const data = (await postJson("https://report.netcraft.com/api/v3/report/urls", {
    email,
    reason: reason.slice(0, 10000),
    urls: urls.map((url) => ({ url })),
  })) as { uuid?: string };
  return data.uuid ? `Netcraft submission ${data.uuid}` : "submitted";
}

/** Report a whole phishing e-mail (raw RFC 822) to Netcraft. */
export async function netcraftMail(email: string, rawMessage: string): Promise<string> {
  const data = (await postJson("https://report.netcraft.com/api/v3/report/mail", { email, message: rawMessage })) as {
    uuid?: string;
  };
  return data.uuid ? `Netcraft submission ${data.uuid}` : "submitted";
}

/**
 * Cloudflare abuse-report API. Needs an API token with "Trust and Safety Write" and the
 * abuse-reports entitlement on the account (ask Cloudflare to enable it). One hostname per call.
 */
export async function cloudflarePhishing(opts: {
  token: string;
  accountId: string;
  name: string;
  email: string;
  urls: string[];
  justification: string;
}): Promise<string[]> {
  const byHost = new Map<string, string[]>();
  for (const u of opts.urls) {
    const h = new URL(u).hostname;
    byHost.set(h, [...(byHost.get(h) ?? []), u]);
  }
  const ids: string[] = [];
  for (const urls of byHost.values()) {
    const data = (await postJson(
      `https://api.cloudflare.com/client/v4/accounts/${opts.accountId}/abuse-reports/abuse_phishing`,
      {
        act: "abuse_phishing",
        name: opts.name,
        email: opts.email,
        email2: opts.email,
        urls: urls.join("\n"),
        justification: opts.justification.slice(0, 5000),
        host_notification: "send",
        // The site owner is the scammer: never send them the reporter's details.
        owner_notification: "none",
      },
      { authorization: `Bearer ${opts.token}` },
    )) as { result?: string | { id?: string } };
    const id = typeof data.result === "string" ? data.result : data.result?.id;
    ids.push(id ?? "submitted");
  }
  return ids;
}

/** Public urlscan.io scan: a safe link abuse desks can open instead of the live scam. */
export async function urlscan(key: string, url: string, tags: string[]): Promise<string> {
  const data = (await postJson(
    "https://urlscan.io/api/v1/scan/",
    { url, visibility: "public", tags: ["scamdown", ...tags].slice(0, 10) },
    { "api-key": key },
  )) as { result?: string };
  if (!data.result) throw new Error("urlscan returned no result link");
  return data.result;
}
