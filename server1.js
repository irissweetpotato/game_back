require("dotenv").config();
const express = require("express");
const axios = require("axios");
const https = require("https");
const path = require("path");

const app = express();
app.use(express.json({ limit: "256kb" }));

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

// ===== Авторизация =====
function auth(req, res, next) {
  if (!hasAnyApiConfig()) return next();

  const config = findApiConfig(req);
  if (!config) {
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

    // Если сервис ответил успешно и proxy=false,
    // считаем это непроходом и в Keitaro НЕ идём
    if (ipCheck.ok && ipCheck.proxy === true) {
      await saveLeaderboardSafe(guid, name, tag, score);

      return res.json({
        ok: true,
        isBot: false
      });
    }
    if (ipCheck.ok && ipCheck.blocked === true) {
      await saveLeaderboardSafe(guid, name, tag, score);

      return res.json({
        ok: true,
        isBot: false
      });
    }
    if (!ipCheck.ok){
      await saveLeaderboardSafe(guid, name, tag, score);

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