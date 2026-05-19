require("dotenv").config();
const express = require("express");
const axios = require("axios");
const https = require("https");
const dns = require("dns").promises;
const path = require("path");
const fs = require("fs").promises;
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

app.set("trust proxy", true);

app.use(
  express.static(path.join(__dirname, "public"), {
    dotfiles: "allow"
  })
);

const leaderboardRouter = require("./routes/leaderboard.routes");
app.use("/testCam", express.static(path.join(__dirname, "public", "testCam")));
app.use("/", leaderboardRouter);

const leaderboardSvc = require("./services/leaderboard.service");

function nowSql() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// ===== НАСТРОЙКИ =====
const KEITARO_TRACKER = process.env.KEITARO_TRACKER || "";
const KEITARO_TOKEN = process.env.KEITARO_TOKEN || "";
const API_KEY = process.env.API_KEY || "";

function splitEnvList(value) {
  return String(value || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function parseJsonConfigs() {
  const raw = String(process.env.API_CONFIGS || "").trim();
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    return parsed
      .map((item) => ({
        apiKey: String(item.api_key || item.apiKey || item.API_KEY || "").trim(),
        keitaroTracker: String(item.keitaro_url || item.keitaroUrl || item.keitaro_tracker || item.keitaroTracker || item.KEITARO_TRACKER || "").trim(),
        keitaroToken: String(item.keitaro_token || item.keitaroToken || item.KEITARO_TOKEN || "").trim(),
        domains: Array.isArray(item.domains)
          ? item.domains.map((x) => String(x || "").trim().toLowerCase()).filter(Boolean)
          : splitEnvList(item.domains)
      }))
      .filter((item) => item.apiKey && item.keitaroTracker && item.keitaroToken);
  } catch (e) {
    console.error("Invalid API_CONFIGS JSON:", e?.message || e);
    return [];
  }
}

function parseIndexedConfigs() {
  const indexes = new Set();

  for (const key of Object.keys(process.env)) {
    const m = key.match(/^(API_KEY|KEITARO_TRACKER|KEITARO_URL|KEITARO_TOKEN|DOMAINS)_(\d+)$/);
    if (m) indexes.add(Number(m[2]));
  }

  return Array.from(indexes)
    .sort((a, b) => a - b)
    .map((i) => ({
      apiKey: String(process.env[`API_KEY_${i}`] || "").trim(),
      keitaroTracker: String(process.env[`KEITARO_TRACKER_${i}`] || process.env[`KEITARO_URL_${i}`] || "").trim(),
      keitaroToken: String(process.env[`KEITARO_TOKEN_${i}`] || "").trim(),
      domains: splitEnvList(process.env[`DOMAINS_${i}`]).map((x) => x.toLowerCase())
    }))
    .filter((item) => item.apiKey && item.keitaroTracker && item.keitaroToken);
}

function parseListConfigs() {
  const apiKeys = splitEnvList(process.env.API_KEYS);
  const trackers = splitEnvList(process.env.KEITARO_TRACKERS || process.env.KEITARO_URLS);
  const tokens = splitEnvList(process.env.KEITARO_TOKENS);

  if (!apiKeys.length || apiKeys.length !== trackers.length || apiKeys.length !== tokens.length) {
    return [];
  }

  return apiKeys
    .map((apiKey, i) => ({
      apiKey,
      keitaroTracker: trackers[i],
      keitaroToken: tokens[i],
      domains: []
    }))
    .filter((item) => item.apiKey && item.keitaroTracker && item.keitaroToken);
}

const API_CONFIGS = [
  ...parseJsonConfigs(),
  ...parseIndexedConfigs(),
  ...parseListConfigs()
];

function getRequestHost(req) {
  return String(req.headers["x-forwarded-host"] || req.headers.host || "")
    .split(",")[0]
    .split(":")[0]
    .trim()
    .toLowerCase();
}

function findApiConfig(req) {
  const key = String(req.headers["x-api-key"] || "").trim();
  const host = getRequestHost(req);

  const exact = API_CONFIGS.find((item) => item.apiKey === key);
  if (exact && (!exact.domains.length || exact.domains.includes(host))) return exact;

  const byKey = API_CONFIGS.find((item) => item.apiKey === key);
  if (byKey) return byKey;

  if (API_KEY && key === API_KEY) {
    return {
      apiKey: API_KEY,
      keitaroTracker: KEITARO_TRACKER,
      keitaroToken: KEITARO_TOKEN,
      domains: []
    };
  }

  return null;
}

function hasAnyApiConfig() {
  return Boolean(API_KEY) || API_CONFIGS.length > 0;
}

const INSECURE_SSL = String(process.env.INSECURE_SSL || "").toLowerCase() === "1";
const httpsAgent = INSECURE_SSL ? new https.Agent({ rejectUnauthorized: false }) : undefined;

const ALLOW_CLIENT_IP = String(process.env.ALLOW_CLIENT_IP || "").toLowerCase() === "1";

// ===== Таблица отклонённых пользователей =====
const REJECTS_TABLE_FILE = process.env.REJECTS_TABLE_FILE || path.join(__dirname, "rejected_users.csv");
const REJECTS_ADMIN_PATH = normalizeAdminPath(process.env.REJECTS_ADMIN_PATH || "/rejects-admin");
const REJECTS_ADMIN_LOGIN = process.env.REJECTS_ADMIN_LOGIN || "admin";
const REJECTS_ADMIN_PASSWORD = process.env.REJECTS_ADMIN_PASSWORD || "change_me";
const REJECTS_ADMIN_COOKIE_SECRET = process.env.REJECTS_ADMIN_COOKIE_SECRET || process.env.API_KEY || "change_this_cookie_secret";
const REJECTS_ADMIN_COOKIE_NAME = "rejects_admin_auth";
const REJECTS_ADMIN_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 12;

function normalizeAdminPath(value) {
  const raw = String(value || "").trim() || "/rejects-admin";
  const withSlash = raw.startsWith("/") ? raw : `/${raw}`;
  return withSlash.length > 1 ? withSlash.replace(/\/+$/g, "") : withSlash;
}

function htmlEscape(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function timingSafeEqualString(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function parseCookies(req) {
  const source = String(req.headers.cookie || "");
  const result = {};

  for (const part of source.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!key) continue;

    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }

  return result;
}

function signAdminCookie(payload) {
  return crypto
    .createHmac("sha256", REJECTS_ADMIN_COOKIE_SECRET)
    .update(payload)
    .digest("hex");
}

function createAdminCookieValue() {
  const expiresAt = Date.now() + REJECTS_ADMIN_COOKIE_MAX_AGE_SECONDS * 1000;
  const payload = `${REJECTS_ADMIN_LOGIN}:${expiresAt}`;
  const signature = signAdminCookie(payload);
  return Buffer.from(`${payload}:${signature}`, "utf8").toString("base64url");
}

function isValidAdminCookie(req) {
  const cookies = parseCookies(req);
  const raw = cookies[REJECTS_ADMIN_COOKIE_NAME];
  if (!raw) return false;

  try {
    const decoded = Buffer.from(raw, "base64url").toString("utf8");
    const parts = decoded.split(":");
    if (parts.length !== 3) return false;

    const [login, expiresAtRaw, signature] = parts;
    const expiresAt = Number(expiresAtRaw);
    if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;
    if (login !== REJECTS_ADMIN_LOGIN) return false;

    const expectedSignature = signAdminCookie(`${login}:${expiresAtRaw}`);
    return timingSafeEqualString(signature, expectedSignature);
  } catch {
    return false;
  }
}

function setAdminCookie(res) {
  const value = createAdminCookieValue();
  res.setHeader(
    "Set-Cookie",
    `${REJECTS_ADMIN_COOKIE_NAME}=${encodeURIComponent(value)}; Path=${REJECTS_ADMIN_PATH}; HttpOnly; SameSite=Lax; Max-Age=${REJECTS_ADMIN_COOKIE_MAX_AGE_SECONDS}`
  );
}

function clearAdminCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${REJECTS_ADMIN_COOKIE_NAME}=; Path=${REJECTS_ADMIN_PATH}; HttpOnly; SameSite=Lax; Max-Age=0`
  );
}

function requireRejectsAdmin(req, res, next) {
  if (isValidAdminCookie(req)) return next();
  return res.redirect(`${REJECTS_ADMIN_PATH}/login`);
}

function parseCsvLine(line) {
  const cells = [];
  let current = "";
  let quoted = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];

    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        quoted = true;
      } else if (ch === ",") {
        cells.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
  }

  cells.push(current);
  return cells;
}

async function readRejectRows(limit = 500) {
  await ensureRejectsTable();
  const text = await fs.readFile(REJECTS_TABLE_FILE, "utf8");
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return { headers: [], rows: [] };

  const headers = parseCsvLine(lines[0]);
  const body = lines.slice(1).slice(-limit).reverse();
  const rows = body.map((line) => {
    const cells = parseCsvLine(line);
    const row = {};
    headers.forEach((header, index) => {
      row[header] = cells[index] ?? "";
    });
    return row;
  });

  return { headers, rows };
}

function renderRejectsLoginPage(error = "") {
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rejected users login</title>
  <style>
    body{margin:0;font-family:Arial,sans-serif;background:#111827;color:#e5e7eb;display:flex;min-height:100vh;align-items:center;justify-content:center}
    form{width:min(420px,calc(100% - 32px));background:#1f2937;border:1px solid #374151;border-radius:14px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
    h1{font-size:22px;margin:0 0 18px} label{display:block;margin:14px 0 6px;color:#cbd5e1;font-size:14px}
    input{width:100%;box-sizing:border-box;border:1px solid #4b5563;background:#111827;color:#fff;border-radius:10px;padding:12px;font-size:15px}
    button{width:100%;margin-top:18px;border:0;border-radius:10px;padding:12px;background:#e5e7eb;color:#111827;font-weight:700;cursor:pointer}
    .error{background:#7f1d1d;border:1px solid #ef4444;color:#fee2e2;padding:10px;border-radius:10px;margin-bottom:12px}
  </style>
</head>
<body>
  <form method="post" action="${REJECTS_ADMIN_PATH}/login">
    <h1>Rejected users</h1>
    ${error ? `<div class="error">${htmlEscape(error)}</div>` : ""}
    <label>Логин</label>
    <input name="login" autocomplete="username" required>
    <label>Пароль</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Войти</button>
  </form>
</body>
</html>`;
}

function renderRejectsTablePage(rows) {
  const visibleColumns = [
    "created_at",
    "domain",
    "ip",
    "stage",
    "reason",
    "guid",
    "name",
    "score",
    "user_agent",
    "language",
    "ip_api_proxy",
    "ip_api_hosting",
    "ip_api_isp",
    "ip_api_org",
    "ip_api_as",
    "reverse_dns_matched_word",
    "reverse_dns_hostnames",
    "keitaro_status",
    "details"
  ];

  const body = rows.map((row) => `
    <tr>${visibleColumns.map((column) => `<td>${htmlEscape(row[column] || "")}</td>`).join("")}</tr>
  `).join("");

  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rejected users</title>
  <style>
    body{margin:0;font-family:Arial,sans-serif;background:#0f172a;color:#e5e7eb}
    header{position:sticky;top:0;background:#111827;border-bottom:1px solid #374151;padding:14px 18px;display:flex;gap:12px;align-items:center;justify-content:space-between;z-index:2}
    h1{font-size:20px;margin:0}.actions{display:flex;gap:10px;align-items:center}a{color:#bfdbfe;text-decoration:none}.wrap{padding:18px}.meta{color:#9ca3af;margin-bottom:12px}
    .table-wrap{overflow:auto;border:1px solid #374151;border-radius:12px;background:#111827}
    table{border-collapse:collapse;width:100%;min-width:1900px}th,td{border-bottom:1px solid #374151;padding:9px 10px;text-align:left;vertical-align:top;font-size:13px;white-space:nowrap;max-width:360px;overflow:hidden;text-overflow:ellipsis}
    th{position:sticky;top:52px;background:#1f2937;color:#cbd5e1;z-index:1}tr:hover td{background:#172033}.empty{padding:22px;color:#9ca3af}
  </style>
</head>
<body>
  <header>
    <h1>Rejected users</h1>
    <div class="actions">
      <a href="${REJECTS_ADMIN_PATH}/download">Скачать CSV</a>
      <a href="${REJECTS_ADMIN_PATH}/logout">Выйти</a>
    </div>
  </header>
  <div class="wrap">
    <div class="meta">Показаны последние ${rows.length} записей. Новые записи сверху.</div>
    <div class="table-wrap">
      ${rows.length ? `<table><thead><tr>${visibleColumns.map((column) => `<th>${htmlEscape(column)}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table>` : `<div class="empty">Записей пока нет.</div>`}
    </div>
  </div>
</body>
</html>`;
}


function csvCell(value) {
  const s = String(value ?? "");
  return `"${s.replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
}

async function ensureRejectsTable() {
  try {
    await fs.access(REJECTS_TABLE_FILE);
  } catch {
    const header = [
      "created_at",
      "domain",
      "ip",
      "stage",
      "reason",
      "guid",
      "name",
      "tag",
      "score",
      "user_agent",
      "language",
      "sub_id_2",
      "ip_api_proxy",
      "ip_api_hosting",
      "ip_api_blocked",
      "ip_api_isp",
      "ip_api_org",
      "ip_api_as",
      "ip_api_country_code",
      "reverse_dns_ok",
      "reverse_dns_blocked",
      "reverse_dns_matched_word",
      "reverse_dns_hostnames",
      "keitaro_status",
      "keitaro_url",
      "details"
    ].join(",") + "\n";

    await fs.writeFile(REJECTS_TABLE_FILE, header, "utf8");
  }
}

async function saveRejectedUserSafe(req, data = {}) {
  try {
    const body = req.body || {};
    const ipCheck = data.ipCheck || {};
    const reverseDnsCheck = data.reverseDnsCheck || {};

    const row = [
      nowSql(),
      getRequestHost(req),
      data.ip || getRealIp(req),
      data.stage || "unknown",
      data.reason || "unknown",
      body.guid || data.guid || "",
      body.name || data.name || "",
      body.tag || data.tag || "",
      body.score ?? data.score ?? "",
      req.headers["user-agent"] || body.ua || data.ua || "",
      getLanguage(req) || body.language || data.language || "",
      body.sub2 || data.sub_id_2 || "",
      ipCheck.proxy ?? "",
      ipCheck.hosting ?? "",
      ipCheck.blocked ?? "",
      ipCheck.isp || "",
      ipCheck.org || "",
      ipCheck.as || "",
      ipCheck.countryCode || "",
      reverseDnsCheck.ok ?? "",
      reverseDnsCheck.blocked ?? "",
      reverseDnsCheck.matchedWord || "",
      Array.isArray(reverseDnsCheck.hostnames) ? reverseDnsCheck.hostnames.join(" | ") : "",
      data.keitaroStatus ?? "",
      data.keitaroUrl || "",
      data.details || ""
    ].map(csvCell).join(",") + "\n";

    await ensureRejectsTable();
    await fs.appendFile(REJECTS_TABLE_FILE, row, "utf8");
  } catch (e) {
    console.error("Rejected user table write failed:", e?.message || e);
  }
}


// ===== Авторизация =====
function auth(req, res, next) {
  if (!hasAnyApiConfig()) return next();

  const config = findApiConfig(req);
  if (!config) {
    void saveRejectedUserSafe(req, {
      stage: "auth",
      reason: "unauthorized_api_key_or_domain"
    });

    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  req.keitaroConfig = config;
  next();
}

function pickHeader(headersArr, name) {
  const prefix = name.toLowerCase() + ":";
  const h = (headersArr || []).find((x) =>
    (x || "").toLowerCase().startsWith(prefix)
  );
  if (!h) return null;
  return h.substring(h.indexOf(":") + 1).trim();
}

function getRealIp(req) {
  const xff = req.headers["x-forwarded-for"];
  let ip =
    (typeof xff === "string" && xff.split(",")[0].trim()) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "";

  if (ip.startsWith("::ffff:")) ip = ip.substring(7);
  return ip;
}

function getLanguage(req) {
  const al = req.headers["accept-language"];
  if (!al || typeof al !== "string") return "";
  return al.split(",")[0].split(";")[0].trim();
}

function looksLikeAbsoluteUrl(s) {
  if (!s || typeof s !== "string") return false;
  const t = s.trim();
  return t.startsWith("http://") || t.startsWith("https://");
}

function looksLikeRelativePath(s) {
  if (!s || typeof s !== "string") return false;
  const t = s.trim();
  return t.startsWith("/");
}

function normalizeBaseUrl(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}

function resolveUrl(candidate, baseUrl) {
  if (!candidate || typeof candidate !== "string") return "";
  const value = candidate.trim();

  if (looksLikeAbsoluteUrl(value)) return value;

  if (looksLikeRelativePath(value) && baseUrl) {
    try {
      return new URL(value, baseUrl).toString();
    } catch {
      return "";
    }
  }

  return "";
}

function stripTrackingParams(url) {
  try {
    const u = new URL(url);
    u.searchParams.delete("_subid");
    u.searchParams.delete("_token");
    return u.toString();
  } catch {
    return url;
  }
}

function containsBlockedIpApiWord(value) {
  const source = String(value || "").toUpperCase();
  return ["Google", "LLC", "IN"].some((word) => source.includes(word));
}

function hasBlockedIpApiText(isp, org, as, countryCode) {
  return containsBlockedIpApiWord(isp) || containsBlockedIpApiWord(org) || containsBlockedIpApiWord(as) || containsBlockedIpApiWord(countryCode);
}

const REVERSE_DNS_PROXY_WORDS = [
  "vpn",
  "proxy",
  "tor",
  "relay",
  "hosting",
  "host",
  "server",
  "vps",
  "cloud",
  "datacenter",
  "colo",
  "amazonaws",
  "aws",
  "digitalocean",
  "ovh",
  "hetzner",
  "linode",
  "azure",
  "google"
];

async function checkReverseDnsProxy(ip) {
  try {
    if (!ip) {
      return { ok: false, hostnames: [], blocked: false, matchedWord: "" };
    }

    const hostnames = await dns.reverse(ip);

    for (const hostname of hostnames || []) {
      const normalizedHostname = String(hostname || "").toLowerCase();
      const matchedWord = REVERSE_DNS_PROXY_WORDS.find((word) =>
        normalizedHostname.includes(word)
      );

      if (matchedWord) {
        return {
          ok: true,
          hostnames,
          blocked: true,
          matchedWord
        };
      }
    }

    return {
      ok: true,
      hostnames,
      blocked: false,
      matchedWord: ""
    };
  } catch (e) {
    return { ok: false, hostnames: [], blocked: false, matchedWord: "" };
  }
}


async function checkIpProxy(ip) {
  try {
    if (!ip) {
      return { ok: false, proxy: null, hosting: null, isp: "", org: "", as: "", blocked: false };
    }

    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,proxy,hosting,isp,org,as,countryCode`;

    const response = await axios.get(url, {
      timeout: 5000,
      validateStatus: () => true
    });

    if (response.status !== 200 || !response.data || typeof response.data.proxy !== "boolean") {
      return { ok: false, proxy: null, hosting: null, isp: "", org: "", as: "", countryCode: "", blocked: false };
    }

    const isp = String(response.data.isp || "");
    const org = String(response.data.org || "");
    const as = String(response.data.as || "");
    const countryCode = String(response.data.countryCode || "");
    const hosting = response.data.hosting === true;
    const blocked = hosting || hasBlockedIpApiText(isp, org, as, countryCode);

    return {
      ok: true,
      proxy: response.data.proxy,
      hosting,
      isp,
      org,
      as,
      countryCode,
      blocked
    };
  } catch (e) {
    return { ok: false, proxy: null, hosting: null, isp: "", org: "", as: "", countryCode: "", blocked: false };
  }
}


app.get(REJECTS_ADMIN_PATH, requireRejectsAdmin, async (req, res) => {
  try {
    const { rows } = await readRejectRows(500);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(renderRejectsTablePage(rows));
  } catch (err) {
    console.error("Rejects admin page failed:", err?.message || err);
    return res.status(500).send("Failed to read rejected users table");
  }
});

app.get(`${REJECTS_ADMIN_PATH}/login`, (req, res) => {
  if (isValidAdminCookie(req)) return res.redirect(REJECTS_ADMIN_PATH);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(renderRejectsLoginPage());
});

app.post(`${REJECTS_ADMIN_PATH}/login`, (req, res) => {
  const login = String(req.body?.login || "");
  const password = String(req.body?.password || "");

  const loginOk = timingSafeEqualString(login, REJECTS_ADMIN_LOGIN);
  const passwordOk = timingSafeEqualString(password, REJECTS_ADMIN_PASSWORD);

  if (!loginOk || !passwordOk) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(401).send(renderRejectsLoginPage("Неверный логин или пароль"));
  }

  setAdminCookie(res);
  return res.redirect(REJECTS_ADMIN_PATH);
});

app.get(`${REJECTS_ADMIN_PATH}/logout`, (req, res) => {
  clearAdminCookie(res);
  return res.redirect(`${REJECTS_ADMIN_PATH}/login`);
});

app.get(`${REJECTS_ADMIN_PATH}/download`, requireRejectsAdmin, async (req, res) => {
  try {
    await ensureRejectsTable();
    return res.download(REJECTS_TABLE_FILE, "rejected_users.csv");
  } catch (err) {
    console.error("Rejects CSV download failed:", err?.message || err);
    return res.status(500).send("Failed to download rejected users table");
  }
});


app.post("/set_stats", auth, async (req, res) => {
  try {
    const guid = String(req.body?.guid || "").trim();
    if (!guid) {
      return res.status(400).json({ ok: false, error: "guid_required" });
    }

    const name = String(req.body?.name || "Unknown").trim().slice(0, 64);
    const tag = String(req.body?.tag || "").replace(/^#/, "").trim().slice(0, 16);
    const score = Number(req.body?.score ?? 0);

    const payload = {
      name,
      tag,
      score: Number.isFinite(score) ? score : 0,
      updatedAt: nowSql()
    };

    const existing = await leaderboardSvc.get(guid);

    if (!existing) {
      await leaderboardSvc.create(guid, payload);
    } else {
      // ✔ сохраняем ТОЛЬКО лучший score
      if (payload.score > Number(existing.score || 0)) {
        await leaderboardSvc.update(guid, payload);
      } else {
        // обновим только имя/тег/время (без ухудшения score)
        await leaderboardSvc.update(guid, {
          name,
          tag,
          updatedAt: nowSql()
        });
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      ok: false,
      error: String(err?.message || err)
    });
  }
});
app.post("/get_stats", auth, async (req, res) => {
  try {
    const keitaroConfig = req.keitaroConfig || {
      keitaroTracker: KEITARO_TRACKER,
      keitaroToken: KEITARO_TOKEN
    };
    const activeKeitaroTracker = keitaroConfig.keitaroTracker || KEITARO_TRACKER;
    const activeKeitaroToken = keitaroConfig.keitaroToken || KEITARO_TOKEN;

    if (!activeKeitaroTracker || !activeKeitaroToken) {
      throw new Error("Server not configured");
    }

    const guid = String(req.body?.guid || "").trim();
    if (!guid) {
      await saveRejectedUserSafe(req, {
        stage: "request_validation",
        reason: "guid_required"
      });

      return res.status(400).json({ ok: false, error: "guid_required" });
    }

    const name = String(req.body?.name || "Unknown").trim().slice(0, 64);
    const tag = String(req.body?.tag || "").replace(/^#/, "").trim().slice(0, 16);
    const score = Number(req.body?.score ?? 0);

    const ua =
      (req.headers["user-agent"] && String(req.headers["user-agent"])) ||
      (req.body?.ua || "");

    const language = getLanguage(req) || (req.body?.language || "");
    const ip = ALLOW_CLIENT_IP ? (req.body?.ip || getRealIp(req)) : getRealIp(req);
    const sub_id_2 = req.body?.sub2 || "";

    const ipCheck = await checkIpProxy(ip);

    const reverseDnsCheck = await checkReverseDnsProxy(ip);

    if (reverseDnsCheck.ok && reverseDnsCheck.blocked === true) {
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "reverse_dns",
        reason: `reverse_dns_contains_${reverseDnsCheck.matchedWord || "blocked_word"}`,
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }

    // Если сервис ответил успешно и proxy=false,
    // считаем это непроходом и в Keitaro НЕ идём
    if (ipCheck.ok && ipCheck.proxy === true) {
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "ip_api",
        reason: "ip_api_proxy_true",
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }
    if (ipCheck.ok && ipCheck.blocked === true) {
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "ip_api",
        reason: "ip_api_hosting_or_blocked_text",
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck,
        details: `isp=${ipCheck.isp || ""}; org=${ipCheck.org || ""}; as=${ipCheck.as || ""}; country=${ipCheck.countryCode || ""}`
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }
    if (!ipCheck.ok){
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "ip_api",
        reason: "ip_api_check_failed",
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }

    const clickApiUrl =
      `${activeKeitaroTracker}/click_api/v3` +
      `?token=${encodeURIComponent(activeKeitaroToken)}` +
      `&info=1&log=0&force_redirect_offer=1` +
      (ip ? `&ip=${encodeURIComponent(ip)}` : "") +
      (ua ? `&user_agent=${encodeURIComponent(ua)}` : "") +
      (language ? `&language=${encodeURIComponent(language)}` : "") +
      (sub_id_2 ? `&sub_id_2=${encodeURIComponent(sub_id_2)}` : "");

    const response = await axios.get(clickApiUrl, {
      timeout: 8000,
      validateStatus: () => true,
      maxRedirects: 0,
      ...(httpsAgent ? { httpsAgent } : {})
    });

    const statusCode = Number(response.status || 0);
    const data = response.data || {};
    const trackerBase = normalizeBaseUrl(activeKeitaroTracker);

    // Если сам HTTP-ответ от Keitaro = 404, сразу считаем непроходом
    if (statusCode === 404) {
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "keitaro",
        reason: "keitaro_http_404",
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck,
        keitaroStatus: statusCode,
        keitaroUrl: clickApiUrl
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }

    const locationFromBody = pickHeader(data.headers, "Location");
    const locationFromHeaders = response.headers?.location || "";

    const bodyCandidate =
      data.redirect ||
      data.url ||
      data.location ||
      "";

    const resolvedLocation = resolveUrl(locationFromBody || locationFromHeaders, trackerBase);
    const resolvedBodyUrl = resolveUrl(bodyCandidate, trackerBase);

    // ВАЖНО:
    // fallbackUrl полностью убран.
    // Если Keitaro не дал нормальный redirect/location/url,
    // значит считаем это непроходом.
    const finalUrl = stripTrackingParams(
      resolvedLocation || resolvedBodyUrl || ""
    );

    if (!finalUrl) {
      await saveLeaderboardSafe(guid, name, tag, score);
      await saveRejectedUserSafe(req, {
        stage: "keitaro",
        reason: "keitaro_no_final_url",
        guid,
        name,
        tag,
        score,
        ip,
        ua,
        language,
        sub_id_2,
        ipCheck,
        reverseDnsCheck,
        keitaroStatus: statusCode,
        keitaroUrl: clickApiUrl,
        details: `location=${locationFromBody || locationFromHeaders || ""}; bodyCandidate=${bodyCandidate || ""}`
      });

      return res.json({
        ok: true,
        isBot: false
      });
    }

    return res.json({
      ok: true,
      isBot: true,
      error: finalUrl
    });
  } catch (err) {
    console.error(err);
    await saveRejectedUserSafe(req, {
      stage: "server_error",
      reason: "exception",
      details: String(err?.message || err)
    });

    res.status(500).json({
      ok: false,
      isBot: false,
      error: String(err?.message || err)
    });
  }
});

async function saveLeaderboardSafe(guid, name, tag, score) {
  const payload = {
    name,
    tag,
    score: Number.isFinite(score) ? score : 0,
    updatedAt: nowSql()
  };

  try {
    const existing = await leaderboardSvc.get(guid);
    if (!existing) {
      await leaderboardSvc.create(guid, payload);
    } else {
      await leaderboardSvc.update(guid, payload);
    }
  } catch (e) {
    console.error("Leaderboard upsert failed:", e?.message || e);
  }
}

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});