"use strict";
// Translations live in /locales/<code>.json. To add a language: add the file and one line here.
const LANGS = { en: "English", tr: "Türkçe", es: "Español", de: "Deutsch", fr: "Français", pt: "Português" };
// Countries with a national reporting desk (src/providers.ts AUTHORITIES), guessed from the browser.
const COUNTRIES = ["TR", "GB", "US"];
const TESSERACT = { src: "https://cdn.jsdelivr.net/npm/tesseract.js@7.0.0/dist/tesseract.min.js", integrity: "sha384-2BQ3U3OdKOb0Uczxqr41I9UvZkzr4V9Hv8uSzMMZAlmhsFClvdZX5wi5fDCzG+tM" };

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- language ----------
const pick = () => {
  if (LANGS[localStorage.lang]) return localStorage.lang;
  for (const l of navigator.languages || [navigator.language]) if (LANGS[l.slice(0, 2)]) return l.slice(0, 2);
  return "en";
};
let dict = {};
const cache = {};
const load = (code) => (cache[code] ??= fetch(`/locales/${code}.json`).then((r) => r.json()).catch(() => ({})));
const t = (k, vars = {}) => (dict[k] ?? k).replace(/\{(\w+)\}/g, (_, v) => vars[v] ?? "");
/** Translated text for HTML templates: escaped, so a locale file can't inject markup. */
const h = (k, vars) => esc(t(k, vars));
async function setLang(code) {
  const [en, own] = await Promise.all([load("en"), code === "en" ? {} : load(code)]);
  dict = { ...en, ...own };
  document.documentElement.lang = code;
  document.title = t("title");
  document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
  document.querySelectorAll("[data-tp]").forEach((el) => (el.placeholder = t(el.dataset.tp)));
  if (last) render(last);
}
$("lang").innerHTML = Object.entries(LANGS).map(([c, n]) => `<option value="${c}">${n}</option>`).join("");
$("lang").value = pick();
$("lang").onchange = () => { localStorage.lang = $("lang").value; setLang($("lang").value); };

const country = (navigator.languages || []).map((l) => l.split("-")[1]?.toUpperCase()).find((r) => COUNTRIES.includes(r)) ?? "";

// ---------- server ----------
const status = (msg, err) => { $("status").textContent = msg || ""; $("status").className = "status" + (err ? " err" : ""); };
async function api(path, body) {
  const res = await fetch(path, { method: body ? "POST" : "GET", headers: { "content-type": "application/json" }, body: body && JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status });
  return data;
}
const configP = api("/api/config").catch(() => ({}));
let config = {};
configP.then((c) => { config = c; if (last) render(last); });

function loadScript(src, integrity) {
  return new Promise((ok, fail) => {
    const s = document.createElement("script");
    s.src = src;
    if (integrity) { s.integrity = integrity; s.crossOrigin = "anonymous"; }
    s.onload = ok;
    s.onerror = () => fail(new Error(`could not load ${new URL(src).host}`));
    document.head.append(s);
  });
}

// ---------- screenshot ----------
let shot = null;
function setShot(file) {
  if (!file || !file.type.startsWith("image/")) return;
  shot = file;
  $("shotImg").src = URL.createObjectURL(file);
  $("shotName").textContent = file.name || "screenshot";
  $("shot").hidden = false;
  $("pickShot").hidden = true;
}
$("shotClear").onclick = () => { shot = null; $("shot").hidden = true; $("pickShot").hidden = false; $("file").value = ""; };
$("pickShot").onclick = () => $("file").click();
$("file").onchange = (e) => { setShot(e.target.files[0]); $("go").click(); };
document.addEventListener("paste", (e) => {
  const item = [...(e.clipboardData?.items ?? [])].find((i) => i.type.startsWith("image/"));
  if (item) { e.preventDefault(); setShot(item.getAsFile()); }
  // Pasting is the whole intent, so check right away.
  if (item || e.target === $("text")) setTimeout(() => $("go").disabled || $("go").click(), 0);
});
const drop = $("drop");
drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); setShot(e.dataTransfer.files[0]); if (shot) $("go").click(); };

const toBase64 = (blob) => new Promise((ok) => { const r = new FileReader(); r.onload = () => ok(String(r.result).split(",")[1]); r.readAsDataURL(blob); });

async function ocrInBrowser(file) {
  if (!window.Tesseract) await loadScript(TESSERACT.src, TESSERACT.integrity);
  const { data } = await Tesseract.recognize(file, "eng");
  return data.text;
}

// ---------- check ----------
let last = null;
$("go").onclick = async () => {
  $("go").disabled = true;
  try {
    await configP;
    let text = $("text").value;
    let found = { urls: [] };
    if (shot) {
      status(t("reading"));
      try {
        if (!config.vision) throw Object.assign(new Error(), { status: 501 });
        found = await api("/api/extract", { image: { data: await toBase64(shot), mime: shot.type } });
      } catch (e) {
        if (e.status !== 501) throw e;
        text += "\n" + (await ocrInBrowser(shot));
      }
    }
    if (text.trim()) {
      const more = await api("/api/extract", { text });
      found.urls = [...new Set([...found.urls, ...more.urls])];
    }
    if (!found.urls.length) return status(t("none"), true);
    status(t("checking"));
    const via = found.summary ? (found.kind ? found.kind.toUpperCase() + (found.phones?.[0] ? " " + found.phones[0] : "") + ": " : "") + found.summary : undefined;
    last = await api("/api/plan", { urls: found.urls, category: "phishing", brand: found.brand, via, country });
    render(last);
    status("");
    $("results").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  } catch (e) {
    status(e.message, true);
  } finally {
    $("go").disabled = false;
  }
};

// ---------- results ----------
const keyOf = (tg) => tg.id + "|" + tg.urls.join(",");
const doneSet = () => new Set(JSON.parse(localStorage.done || "[]"));
/** The one way each place gets reported: Netcraft's API, the connected mailbox, else its form or a mail draft. */
function action(tg) {
  const netcraft = tg.channels.find((c) => c.kind === "api" && c.api === "netcraft");
  if (netcraft && config.netcraft) return netcraft;
  const mail = tg.channels.find((c) => c.kind === "email");
  if (mail && mailbox) return mail;
  return tg.channels.find((c) => c.kind === "form" || c.kind === "email");
}
const isAuto = (c) => c && (c.kind === "api" || (c.kind === "email" && mailbox));

function render(plan) {
  $("results").hidden = false;
  $("how").hidden = true;
  $("links").innerHTML = plan.links.map((l) => `
    <div class="url"><span class="pill ${l.alive ? "live" : "down"}"><i></i>${h(l.alive ? "live" : "down")}</span>
      <code>${esc(l.url)}</code>
      <details><summary>${h("details")}</summary>
        ${l.hops.slice(1).map((x) => `<div>→ ${esc(x.url)}</div>`).join("")}
        ${l.hosts.map((x) => `<div>${esc(x.host)} · ${esc(x.ips.join(", ") || "-")}${x.asn ? ` · AS${x.asn.number} ${esc(x.asn.name)}` : ""}</div>`).join("")}
        ${l.warnings.map((w) => `<div>! ${esc(w)}</div>`).join("")}
      </details>
    </div>`).join("");

  const done = doneSet();
  const auto = plan.targets.filter((tg) => isAuto(action(tg)) && !done.has(keyOf(tg))).length;
  $("sendAll").hidden = auto === 0;
  $("sendAll").textContent = t("sendAll", { n: auto });
  renderMailbox(plan);
  $("progressRow").hidden = !plan.targets.length;
  if (!plan.targets.length) return void ($("targets").innerHTML = `<li>${h("gone")}</li>`);

  $("targets").innerHTML = plan.targets.map((tg, i) => {
    const c = action(tg);
    const d = tg.draft || {};
    let button = "";
    if (isAuto(c)) button = `<button class="btn" type="button" data-act="send" data-i="${i}">${h("report")}</button>`;
    else if (c?.kind === "form") button = `<a class="btn" href="${esc(c.url)}" target="_blank" rel="noopener noreferrer" data-act="form" data-i="${i}">${h("openForm")}</a>`;
    else if (c?.kind === "email") button = `<a class="btn" href="mailto:${esc(c.to)}?subject=${encodeURIComponent(d.subject || "")}&amp;body=${encodeURIComponent(d.body || "")}" data-act="open" data-i="${i}">${h("mail")}</a>`;
    const key = keyOf(tg);
    return `<li class="${done.has(key) ? "done" : ""}" data-key="${esc(key)}" data-i="${i}">
      <span class="tick"></span><div class="who"><b>${esc(tg.name)}</b><small>${h("role." + tg.role)}</small></div>
      <span class="result" data-result></span>${button}</li>`;
  }).join("");
  progress(false);
}

/** "3 of 9 reported", and the stamp once every place is done. */
function progress(fresh) {
  const total = last.targets.length;
  const done = document.querySelectorAll("#targets li.done").length;
  $("progress").textContent = t("progress", { done, total });
  $("bar").style.width = total ? `${(100 * done) / total}%` : "0";
  const first = document.querySelector("#links .url");
  if (!first || first.querySelector(".stamp") || done < total || !total) return;
  const stamp = document.createElement("span");
  stamp.className = "stamp";
  stamp.textContent = t("stamp");
  if (!fresh) stamp.style.animation = "none";
  first.append(stamp);
}

function markDone(li) {
  const set = doneSet();
  set.add(li.dataset.key);
  localStorage.done = JSON.stringify([...set]);
  li.classList.add("done");
  progress(true);
}
const row = (i) => document.querySelector(`#targets li[data-i="${i}"]`);
function show(i, msg, cls) {
  const out = row(i)?.querySelector("[data-result]");
  if (out) { out.textContent = msg; out.className = "result" + (cls ? " " + cls : ""); }
}

/** Sends one place's report and shows the outcome on its row. */
async function deliver(i) {
  const tg = last.targets[i];
  const c = action(tg);
  show(i, t("sending"));
  try {
    if (c.kind === "api") {
      await api("/api/netcraft", { token: last.token });
    } else {
      await sendMail(c.to, tg.draft.subject, tg.draft.body);
      api("/api/sent", { token: last.token, target: tg.id }).catch(() => {});
    }
    show(i, t("sent"), "ok");
    markDone(row(i));
    return true;
  } catch (e) {
    show(i, `${t("failed")}: ${e.message}`, "err");
    return false;
  }
}

$("targets").addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const i = Number(el.dataset.i);
  const tg = last.targets[i];
  if (el.dataset.act === "send") {
    el.disabled = true;
    if (!(await deliver(i))) el.disabled = false;
    return;
  }
  // Forms and mail drafts can't be confirmed from here; opening them counts as done.
  if (el.dataset.act === "form") {
    await navigator.clipboard.writeText(tg.draft ? `${tg.draft.subject}\n\n${tg.draft.body}` : "").catch(() => {});
    show(i, t("copied"));
  }
  markDone(row(i));
});

// One after another, right away; a failure doesn't stop the rest.
$("sendAll").onclick = async () => {
  const done = doneSet();
  const jobs = last.targets.map((tg, i) => [i, tg]).filter(([, tg]) => isAuto(action(tg)) && !done.has(keyOf(tg)));
  $("sendAll").disabled = true;
  for (const [i] of jobs) {
    await deliver(i);
    await sleep(400);
  }
  $("sendAll").disabled = false;
  const left = last.targets.filter((tg) => isAuto(action(tg)) && !doneSet().has(keyOf(tg))).length;
  $("sendAll").hidden = left === 0;
  $("sendAll").textContent = t("sendAll", { n: left });
};

// ---------- mailbox ----------
// The browser gets a short-lived token and calls Gmail / Outlook itself. Nothing is stored on the server,
// no refresh token is requested, and the token is forgotten when the tab closes.
let mailbox = null;

function renderMailbox(plan) {
  const box = $("mailbox");
  const hasMail = plan.targets.some((tg) => tg.channels.some((c) => c.kind === "email"));
  box.hidden = !hasMail || !(mailbox || config.google || config.microsoft);
  if (box.hidden) return;
  if (mailbox) {
    box.innerHTML = `${h("connected", { name: mailbox.label })} <button class="link" type="button" id="mbOff">${h("disconnect")}</button>`;
    $("mbOff").onclick = () => { mailbox = null; render(last); };
    return;
  }
  box.innerHTML = `${h("mailboxAsk")} ` + [
    config.google ? `<button class="link" type="button" id="mbGoogle">Gmail</button>` : "",
    config.microsoft ? `<button class="link" type="button" id="mbMs">Outlook</button>` : "",
  ].filter(Boolean).join(" · ");
  if ($("mbGoogle")) $("mbGoogle").onclick = () => connect(connectGmail);
  if ($("mbMs")) $("mbMs").onclick = () => connect(connectOutlook);
}

async function connect(fn) {
  try {
    mailbox = await fn();
    render(last);
  } catch (e) {
    status(e.message, true);
  }
}

async function connectGmail() {
  if (!window.google?.accounts?.oauth2) await loadScript("https://accounts.google.com/gsi/client");
  const r = await new Promise((ok, fail) => {
    google.accounts.oauth2.initTokenClient({
      client_id: config.google,
      scope: "https://www.googleapis.com/auth/gmail.send",
      callback: (res) => (res.error ? fail(new Error(res.error_description || res.error)) : ok(res)),
      error_callback: (err) => fail(new Error(err.message || err.type || "cancelled")),
    }).requestAccessToken();
  });
  return { kind: "gmail", label: "Gmail", token: r.access_token, until: Date.now() + (r.expires_in - 60) * 1000 };
}

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Microsoft identity platform, authorization code + PKCE in a popup. The redirect page relays the code back. */
async function connectOutlook() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const redirect = `${location.origin}/oauth.html`;
  const auth = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
  auth.search = new URLSearchParams({
    client_id: config.microsoft, response_type: "code", redirect_uri: redirect, response_mode: "query",
    scope: "https://graph.microsoft.com/Mail.Send", code_challenge: challenge, code_challenge_method: "S256",
    state, prompt: "select_account",
  }).toString();
  const channel = new BroadcastChannel("scamdown-oauth");
  const query = new Promise((ok, fail) => {
    channel.onmessage = (e) => ok(new URLSearchParams(e.data));
    setTimeout(() => fail(new Error("cancelled")), 5 * 60_000);
  }).finally(() => channel.close());
  window.open(auth, "scamdown-oauth", "width=520,height=700");
  const params = await query;
  if (params.get("state") !== state) throw new Error("login was not completed");
  if (!params.get("code")) throw new Error(params.get("error_description") || "cancelled");
  const res = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: config.microsoft, grant_type: "authorization_code", code: params.get("code"),
      redirect_uri: redirect, code_verifier: verifier, scope: "https://graph.microsoft.com/Mail.Send",
    }),
  });
  const tok = await res.json();
  if (!tok.access_token) throw new Error(tok.error_description || "Outlook login failed");
  return { kind: "outlook", label: "Outlook", token: tok.access_token, until: Date.now() + (tok.expires_in - 60) * 1000 };
}

function utf8b64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
const wrap = (b64) => b64.replace(/.{1,76}/g, "$&\r\n");

async function sendMail(to, subject, body) {
  if (!mailbox) throw new Error("no mailbox");
  if (Date.now() > mailbox.until) { mailbox = null; render(last); throw new Error(t("reconnect")); }
  const attachment = shot ? { name: shot.name || "screenshot.png", type: shot.type, data: await toBase64(shot) } : null;

  if (mailbox.kind === "gmail") {
    const boundary = `sd-${crypto.randomUUID()}`;
    const parts = [
      `To: ${to}`,
      `Subject: =?UTF-8?B?${utf8b64(subject)}?=`,
      "MIME-Version: 1.0",
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      "",
      `--${boundary}`,
      "Content-Type: text/plain; charset=UTF-8",
      "Content-Transfer-Encoding: base64",
      "",
      wrap(utf8b64(body)),
    ];
    if (attachment) {
      parts.push(`--${boundary}`, `Content-Type: ${attachment.type}; name="${attachment.name.replace(/"/g, "")}"`,
        `Content-Disposition: attachment; filename="${attachment.name.replace(/"/g, "")}"`, "Content-Transfer-Encoding: base64", "", wrap(attachment.data));
    }
    parts.push(`--${boundary}--`, "");
    const raw = utf8b64(parts.join("\r\n")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
      method: "POST", headers: { authorization: `Bearer ${mailbox.token}`, "content-type": "application/json" }, body: JSON.stringify({ raw }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error?.message || `Gmail ${res.status}`);
    return;
  }

  const res = await fetch("https://graph.microsoft.com/v1.0/me/sendMail", {
    method: "POST",
    headers: { authorization: `Bearer ${mailbox.token}`, "content-type": "application/json" },
    body: JSON.stringify({
      message: {
        subject, body: { contentType: "Text", content: body }, toRecipients: [{ emailAddress: { address: to } }],
        attachments: attachment ? [{ "@odata.type": "#microsoft.graph.fileAttachment", name: attachment.name, contentType: attachment.type, contentBytes: attachment.data }] : [],
      },
      saveToSentItems: true,
    }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error?.message || `Outlook ${res.status}`);
}

setLang($("lang").value);
