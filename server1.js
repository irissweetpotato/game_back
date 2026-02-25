require("dotenv").config();
const express = require("express");
const axios = require("axios");
const https = require("https");
const path = require("path");


const app = express();
app.use(express.json({ limit: "256kb" }));

app.set("trust proxy", true);

app.use(express.static(path.join(__dirname, "public")));
const leaderboardRouter = require("./routes/leaderboard.routes");
app.use("/", leaderboardRouter);

const leaderboardSvc = require("./services/leaderboard.service");

function nowSql() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// ===== НАСТРОЙКИ =====
const KEITARO_TRACKER = process.env.KEITARO_TRACKER || "";
const KEITARO_TOKEN = process.env.KEITARO_TOKEN || "";
const ALLOW_STREAM_ID = Number(process.env.ALLOW_STREAM_ID || 0);
const API_KEY = process.env.API_KEY || "";

const INSECURE_SSL = String(process.env.INSECURE_SSL || "").toLowerCase() === "1";
const httpsAgent = INSECURE_SSL ? new https.Agent({ rejectUnauthorized: false }) : undefined;

const ALLOW_CLIENT_IP = String(process.env.ALLOW_CLIENT_IP || "").toLowerCase() === "1";

// ===== Авторизация =====
function auth(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers["x-api-key"];
  if (key !== API_KEY) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

function pickHeader(headersArr, name) {
  const prefix = name.toLowerCase() + ":";
  const h = (headersArr || []).find(x =>
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

function looksLikeUrl(s) {
  if (!s || typeof s !== "string") return false;
  const t = s.trim();
  return t.startsWith("http://") || t.startsWith("https://");
}

/**
 * POST /get_stats
 * Body (пример):
 * {
 *   "guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
 *   "name": "Player_1",
 *   "tag": "1337",
 *   "score": 12345,
 *   "ua": "...",        // опционально
 *   "language": "en",   // опционально
 *   "ip": "1.2.3.4",    // опционально, если ALLOW_CLIENT_IP=1
 *   "sub2": "..."       // опционально
 * }
 *
 * Логика:
 * - Всегда upsert записи в лидерборд по guid
 * - Если проходит фильтр (stream_id == ALLOW_STREAM_ID) -> status=true + url
 * - Иначе -> status=false
 */
app.post("/get_stats", auth, async (req, res) => {
  try {
    if (!KEITARO_TRACKER || !KEITARO_TOKEN || !ALLOW_STREAM_ID) {
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

    // --- Keitaro filter request (как у вас было) ---
    const clickApiUrl =
      `${KEITARO_TRACKER}/click_api/v3` +
      `?token=${encodeURIComponent(KEITARO_TOKEN)}` +
      `&info=1&log=0&force_redirect_offer=1` +
      (ip ? `&ip=${encodeURIComponent(ip)}` : "") +
      (ua ? `&user_agent=${encodeURIComponent(ua)}` : "") +
      (language ? `&language=${encodeURIComponent(language)}` : "") +
      (sub_id_2 ? `&sub_id_2=${encodeURIComponent(sub_id_2)}` : "");

    const response = await axios.get(clickApiUrl, {
      timeout: 8000,
      validateStatus: () => true,
      ...(httpsAgent ? { httpsAgent } : {})
    });

    const data = response.data || {};
    const info = data.info || {};
    const streamId = Number(info.stream_id || 0);

    const passed = streamId === Number(ALLOW_STREAM_ID);

    // --- Всегда создаём/обновляем запись в лидерборде ---
    // Если записи нет -> create
    // Если есть -> update (обновляем имя/тег/score/updatedAt)
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
      // Ошибка записи в лидерборд не должна ломать основной ответ.
      // Но логируем, чтобы видеть проблемы с файлом/правами.
      console.error("Leaderboard upsert failed:", e?.message || e);
    }

    // --- Ответ клиенту ---
    if (!passed) {
      return res.json({
        ok: true,
        status: false
      });
    }

    const location = pickHeader(data.headers, "Location");

    const directUrl =
      (looksLikeUrl(data.redirect) && data.redirect) ||
      (looksLikeUrl(data.url) && data.url) ||
      (looksLikeUrl(data.location) && data.location) ||
      (looksLikeUrl(data.body) && data.body) ||
      "";

    const fallbackUrl = info.token
      ? `${KEITARO_TRACKER}/?_lp=1&_token=${encodeURIComponent(info.token)}`
      : "";

    const finalUrl = stripTrackingParams(location || directUrl || fallbackUrl);

    return res.json({
      ok: true,
      status: true,
      url: finalUrl
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      ok: false,
      status: false,
      error: String(err?.message || err)
    });
  }
});
function stripTrackingParams(url) {
  try {
    const u = new URL(url);
    u.searchParams.delete("_subid");
    u.searchParams.delete("_token");
    return u.toString();
  } catch { return url; }
}

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});