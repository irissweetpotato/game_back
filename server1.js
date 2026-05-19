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
          : splitEnvList(item.domains).map((x) => x.toLowerCase()),
        domainName: String(item.domain_name || item.domainName || item.name || item.label || "").trim()
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
      domains: splitEnvList(process.env[`DOMAINS_${i}`]).map((x) => x.toLowerCase()),
      domainName: String(process.env[`DOMAIN_NAME_${i}`] || process.env[`DOMAIN_LABEL_${i}`] || process.env[`NAME_${i}`] || "").trim()
    }))
    .filter((item) => item.apiKey && item.keitaroTracker && item.keitaroToken);
}

function parseListConfigs() {
  const apiKeys = splitEnvList(process.env.API_KEYS);
  const trackers = splitEnvList(process.env.KEITARO_TRACKERS || process.env.KEITARO_URLS);
  const tokens = splitEnvList(process.env.KEITARO_TOKENS);
  const domainNames = splitEnvList(process.env.DOMAIN_NAMES || process.env.DOMAIN_LABELS_LIST);

  if (!apiKeys.length || apiKeys.length !== trackers.length || apiKeys.length !== tokens.length) {
    return [];
  }

  return apiKeys
    .map((apiKey, i) => ({
      apiKey,
      keitaroTracker: trackers[i],
      keitaroToken: tokens[i],
      domains: [],
      domainName: domainNames[i] || ""
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
      domains: [],
      domainName: process.env.DOMAIN_NAME || process.env.DOMAIN_LABEL || ""
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
const REJECTS_ADMIN_TEMPLATE_DIR = path.join(__dirname, "views", "rejects-admin");

// ===== Telegram reject notifications =====
const TELEGRAM_REJECTS_ENABLED = String(process.env.TELEGRAM_REJECTS_ENABLED || "").toLowerCase() === "1";
const TELEGRAM_REJECT_BOT_TOKEN = String(process.env.TELEGRAM_REJECT_BOT_TOKEN || "").trim();
const TELEGRAM_REJECT_CHAT_ID = String(process.env.TELEGRAM_REJECT_CHAT_ID || "").trim();
const TELEGRAM_REJECT_MESSAGE_MAX_LENGTH = 3900;
const DOMAIN_LABELS = parseDomainLabels(process.env.DOMAIN_LABELS || process.env.REJECTS_DOMAIN_LABELS || "");

function parseDomainLabels(value) {
  const raw = String(value || "").trim();
  if (!raw) return {};

  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return Object.fromEntries(
        Object.entries(parsed)
          .map(([domain, label]) => [String(domain || "").trim().toLowerCase(), String(label || "").trim()])
          .filter(([domain, label]) => domain && label)
      );
    }
  } catch {
    // Also support: domain.com=Name,other.com=Other Name
  }

  const result = {};
  for (const part of raw.split(",")) {
    const index = part.indexOf("=");
    if (index === -1) continue;

    const domain = part.slice(0, index).trim().toLowerCase();
    const label = part.slice(index + 1).trim();
    if (domain && label) result[domain] = label;
  }

  return result;
}

function getDomainDisplayName(domain) {
  const normalizedDomain = String(domain || "").trim().toLowerCase();
  if (!normalizedDomain) return "Rejected user";

  if (DOMAIN_LABELS[normalizedDomain]) return DOMAIN_LABELS[normalizedDomain];

  const config = API_CONFIGS.find((item) =>
    item.domainName && Array.isArray(item.domains) && item.domains.includes(normalizedDomain)
  );
  if (config?.domainName) return config.domainName;

  const fallbackConfig = API_CONFIGS.find((item) => item.domainName && (!item.domains || item.domains.length === 0));
  if (fallbackConfig?.domainName) return fallbackConfig.domainName;

  return normalizedDomain;
}

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

async function readRejectRows(options = {}) {
  await ensureRejectsTable();
  const text = await fs.readFile(REJECTS_TABLE_FILE, "utf8");
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return { headers: [], rows: [], domains: [] };

  const headers = parseCsvLine(lines[0]);
  const allRows = lines.slice(1).map((line) => {
    const cells = parseCsvLine(line);
    const row = {};
    headers.forEach((header, index) => {
      row[header] = cells[index] ?? "";
    });
    return row;
  });

  const domains = Array.from(
    new Set(allRows.map((row) => String(row.domain || "").trim()).filter(Boolean))
  ).sort((a, b) => a.localeCompare(b));

  const selectedDomain = String(options.domain || "").trim().toLowerCase();
  const sortOrder = String(options.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
  const limit = Number.isFinite(Number(options.limit)) ? Math.max(1, Number(options.limit)) : 1000;

  const rows = allRows
    .filter((row) => !selectedDomain || String(row.domain || "").trim().toLowerCase() === selectedDomain)
    .sort((a, b) => {
      const aa = String(a.created_at || "");
      const bb = String(b.created_at || "");
      return sortOrder === "asc" ? aa.localeCompare(bb) : bb.localeCompare(aa);
    })
    .slice(0, limit);

  return { headers, rows, domains };
}


async function loadRejectsAdminTemplate(fileName) {
  return await fs.readFile(path.join(REJECTS_ADMIN_TEMPLATE_DIR, fileName), "utf8");
}

function replaceTemplateVars(template, values) {
  return Object.entries(values).reduce(
    (html, [key, value]) => html.replaceAll(`{{${key}}}`, String(value ?? "")),
    template
  );
}

async function renderRejectsLoginPage(error = "") {
  const template = await loadRejectsAdminTemplate("login.html");
  return replaceTemplateVars(template, {
    ADMIN_PATH: htmlEscape(REJECTS_ADMIN_PATH),
    LOGIN_ACTION: htmlEscape(`${REJECTS_ADMIN_PATH}/login`),
    ERROR_BLOCK: error ? `<div class="error">${htmlEscape(error)}</div>` : ""
  });
}

async function renderRejectsTablePage(rows, options = {}) {
  const template = await loadRejectsAdminTemplate("rejects.html");

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

  const headerHtml = visibleColumns
    .map((column) => `<th>${htmlEscape(column)}</th>`)
    .join("");

  const rowsHtml = rows
    .map((row) => `<tr>${visibleColumns.map((column) => `<td>${htmlEscape(row[column] || "")}</td>`).join("")}</tr>`)
    .join("");

  const selectedDomain = String(options.domain || "").trim().toLowerCase();
  const sortOrder = String(options.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
  const domains = Array.isArray(options.domains) ? options.domains : [];
  const domainOptions = [
    `<option value=""${selectedDomain ? "" : " selected"}>All domains</option>`,
    ...domains.map((domain) => {
      const normalizedDomain = String(domain || "").trim().toLowerCase();
      const selected = normalizedDomain === selectedDomain ? " selected" : "";
      const label = getDomainDisplayName(domain);
      const suffix = label && label !== domain ? ` — ${domain}` : domain;
      return `<option value="${htmlEscape(domain)}"${selected}>${htmlEscape(suffix)}</option>`;
    })
  ].join("");

  const filterQuery = new URLSearchParams();
  if (selectedDomain) filterQuery.set("domain", selectedDomain);
  filterQuery.set("order", sortOrder);
  const filterSuffix = filterQuery.toString() ? `?${filterQuery.toString()}` : "";

  return replaceTemplateVars(template, {
    ADMIN_PATH: htmlEscape(REJECTS_ADMIN_PATH),
    DOWNLOAD_URL: htmlEscape(`${REJECTS_ADMIN_PATH}/download${filterSuffix}`),
    LOGOUT_URL: htmlEscape(`${REJECTS_ADMIN_PATH}/logout`),
    FILTER_ACTION: htmlEscape(REJECTS_ADMIN_PATH),
    DOMAIN_OPTIONS: domainOptions,
    ORDER_DESC_SELECTED: sortOrder === "desc" ? "selected" : "",
    ORDER_ASC_SELECTED: sortOrder === "asc" ? "selected" : "",
    ROW_COUNT: String(rows.length),
    GENERATED_AT: htmlEscape(nowSql()),
    TABLE_HEADER: headerHtml,
    TABLE_ROWS: rowsHtml,
    EMPTY_STATE: rows.length ? "" : `<div class="empty">No rejected users yet.</div>`,
    TABLE_DISPLAY: rows.length ? "" : "display:none;"
  });
}

function csvCell(value) {
  const s = String(value ?? "");
  return `"${s.replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
}

function telegramHtmlEscape(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function compactTelegramValue(value, maxLength = 700) {
  const normalized = String(value ?? "").replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) return normalized;
  return normalized.slice(0, Math.max(0, maxLength - 3)) + "...";
}

function buildTelegramRejectText(reject) {
  const lines = [
    `<b>${telegramHtmlEscape(getDomainDisplayName(reject.domain))}</b>`,
    "",
    `<b>Domain:</b> ${telegramHtmlEscape(reject.domain)}`,
    `<b>IP:</b> ${telegramHtmlEscape(reject.ip)}`,
    `<b>Stage:</b> ${telegramHtmlEscape(reject.stage)}`,
    `<b>Reason:</b> ${telegramHtmlEscape(reject.reason)}`,
    "",
    `<b>GUID:</b> ${telegramHtmlEscape(reject.guid)}`,
    `<b>Name:</b> ${telegramHtmlEscape(reject.name)}`,
    `<b>Tag:</b> ${telegramHtmlEscape(reject.tag)}`,
    `<b>Score:</b> ${telegramHtmlEscape(reject.score)}`,
    "",
    `<b>UA:</b> ${telegramHtmlEscape(compactTelegramValue(reject.userAgent, 900))}`,
    `<b>Language:</b> ${telegramHtmlEscape(reject.language)}`,
    `<b>Sub ID 2:</b> ${telegramHtmlEscape(reject.subId2)}`,
    "",
    `<b>ip-api proxy:</b> ${telegramHtmlEscape(reject.ipApiProxy)}`,
    `<b>ip-api hosting:</b> ${telegramHtmlEscape(reject.ipApiHosting)}`,
    `<b>ip-api blocked:</b> ${telegramHtmlEscape(reject.ipApiBlocked)}`,
    `<b>ISP:</b> ${telegramHtmlEscape(compactTelegramValue(reject.ipApiIsp, 300))}`,
    `<b>ORG:</b> ${telegramHtmlEscape(compactTelegramValue(reject.ipApiOrg, 300))}`,
    `<b>AS:</b> ${telegramHtmlEscape(compactTelegramValue(reject.ipApiAs, 300))}`,
    `<b>Country:</b> ${telegramHtmlEscape(reject.ipApiCountryCode)}`,
    "",
    `<b>Reverse DNS ok:</b> ${telegramHtmlEscape(reject.reverseDnsOk)}`,
    `<b>Reverse DNS blocked:</b> ${telegramHtmlEscape(reject.reverseDnsBlocked)}`,
    `<b>Matched word:</b> ${telegramHtmlEscape(reject.reverseDnsMatchedWord)}`,
    `<b>Hostnames:</b> ${telegramHtmlEscape(compactTelegramValue(reject.reverseDnsHostnames, 700))}`,
    "",
    `<b>Keitaro status:</b> ${telegramHtmlEscape(reject.keitaroStatus)}`,
    `<b>Keitaro URL:</b> ${telegramHtmlEscape(compactTelegramValue(reject.keitaroUrl, 700))}`,
    `<b>Details:</b> ${telegramHtmlEscape(compactTelegramValue(reject.details, 700))}`
  ];

  const text = lines.join("\n");
  if (text.length <= TELEGRAM_REJECT_MESSAGE_MAX_LENGTH) return text;

  return text.slice(0, TELEGRAM_REJECT_MESSAGE_MAX_LENGTH - 3) + "...";
}

async function sendTelegramRejectMessageSafe(reject) {
  if (!TELEGRAM_REJECTS_ENABLED) return;
  if (!TELEGRAM_REJECT_BOT_TOKEN || !TELEGRAM_REJECT_CHAT_ID) return;

  try {
    const response = await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_REJECT_BOT_TOKEN}/sendMessage`,
      {
        chat_id: TELEGRAM_REJECT_CHAT_ID,
        text: buildTelegramRejectText(reject),
        parse_mode: "HTML",
        disable_web_page_preview: true
      },
      {
        timeout: 5000,
        validateStatus: () => true
      }
    );

    if (response.status < 200 || response.status >= 300 || response.data?.ok === false) {
      console.error(
        "Telegram reject notification failed:",
        response.status,
        response.data?.description || response.data || "unknown_error"
      );
    }
  } catch (e) {
    console.error("Telegram reject notification failed:", e?.message || e);
  }
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

    const reject = {
      createdAt: nowSql(),
      domain: getRequestHost(req),
      ip: data.ip || getRealIp(req),
      stage: data.stage || "unknown",
      reason: data.reason || "unknown",
      guid: body.guid || data.guid || "",
      name: body.name || data.name || "",
      tag: body.tag || data.tag || "",
      score: body.score ?? data.score ?? "",
      userAgent: req.headers["user-agent"] || body.ua || data.ua || "",
      language: getLanguage(req) || body.language || data.language || "",
      subId2: body.sub2 || data.sub_id_2 || "",
      ipApiProxy: ipCheck.proxy ?? "",
      ipApiHosting: ipCheck.hosting ?? "",
      ipApiBlocked: ipCheck.blocked ?? "",
      ipApiIsp: ipCheck.isp || "",
      ipApiOrg: ipCheck.org || "",
      ipApiAs: ipCheck.as || "",
      ipApiCountryCode: ipCheck.countryCode || "",
      reverseDnsOk: reverseDnsCheck.ok ?? "",
      reverseDnsBlocked: reverseDnsCheck.blocked ?? "",
      reverseDnsMatchedWord: reverseDnsCheck.matchedWord || "",
      reverseDnsHostnames: Array.isArray(reverseDnsCheck.hostnames) ? reverseDnsCheck.hostnames.join(" | ") : "",
      keitaroStatus: data.keitaroStatus ?? "",
      keitaroUrl: data.keitaroUrl || "",
      details: data.details || ""
    };

    const row = [
      reject.createdAt,
      reject.domain,
      reject.ip,
      reject.stage,
      reject.reason,
      reject.guid,
      reject.name,
      reject.tag,
      reject.score,
      reject.userAgent,
      reject.language,
      reject.subId2,
      reject.ipApiProxy,
      reject.ipApiHosting,
      reject.ipApiBlocked,
      reject.ipApiIsp,
      reject.ipApiOrg,
      reject.ipApiAs,
      reject.ipApiCountryCode,
      reject.reverseDnsOk,
      reject.reverseDnsBlocked,
      reject.reverseDnsMatchedWord,
      reject.reverseDnsHostnames,
      reject.keitaroStatus,
      reject.keitaroUrl,
      reject.details
    ].map(csvCell).join(",") + "\n";

    await ensureRejectsTable();
    await fs.appendFile(REJECTS_TABLE_FILE, row, "utf8");
    await sendTelegramRejectMessageSafe(reject);
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
    const domain = String(req.query?.domain || "").trim();
    const order = String(req.query?.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
    const { rows, domains } = await readRejectRows({ domain, order, limit: 1000 });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(await renderRejectsTablePage(rows, { domain, order, domains }));
  } catch (err) {
    console.error("Rejects admin page failed:", err?.message || err);
    return res.status(500).send("Failed to read rejected users table");
  }
});

app.get(`${REJECTS_ADMIN_PATH}/login`, async (req, res) => {
  try {
    if (isValidAdminCookie(req)) return res.redirect(REJECTS_ADMIN_PATH);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(await renderRejectsLoginPage());
  } catch (err) {
    console.error("Rejects login page failed:", err?.message || err);
    return res.status(500).send("Failed to load login page");
  }
});

app.post(`${REJECTS_ADMIN_PATH}/login`, async (req, res) => {
  const login = String(req.body?.login || "");
  const password = String(req.body?.password || "");

  const loginOk = timingSafeEqualString(login, REJECTS_ADMIN_LOGIN);
  const passwordOk = timingSafeEqualString(password, REJECTS_ADMIN_PASSWORD);

  if (!loginOk || !passwordOk) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(401).send(await renderRejectsLoginPage("Invalid username or password"));
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
    const domain = String(req.query?.domain || "").trim();
    const order = String(req.query?.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";

    if (!domain && order === "desc") {
      await ensureRejectsTable();
      return res.download(REJECTS_TABLE_FILE, "rejected_users.csv");
    }

    const { headers, rows } = await readRejectRows({ domain, order, limit: 1000000 });
    const csv = [
      headers.map(csvCell).join(","),
      ...rows.map((row) => headers.map((header) => csvCell(row[header] || "")).join(","))
    ].join("\n") + "\n";

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="rejected_users.csv"');
    return res.send(csv);
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