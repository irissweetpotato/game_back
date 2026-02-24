require("dotenv").config();
const express = require("express");
const axios = require("axios");
const https = require("https");

const app = express();
app.use(express.json({ limit: "256kb" }));

app.set("trust proxy", true);

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

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

/**
 * POST /get_stats
 * - Если boss_completed=true (т.е. streamId == ALLOW_STREAM_ID) -> возвращаем URL и данные Keitaro
 * - Если boss_completed=false -> возвращаем игровые статы (level/exp/...)
 *
 * ВАЖНО: sub_id больше не принимаем и не отправляем в Keitaro.
 */
app.post("/get_stats", auth, async (req, res) => {
  try {
    if (!KEITARO_TRACKER || !KEITARO_TOKEN || !ALLOW_STREAM_ID) {
      throw new Error("Server not configured");
    }

    const ua =
      (req.headers["user-agent"] && String(req.headers["user-agent"])) ||
      (req.body?.ua || "");

    const language = getLanguage(req) || (req.body?.language || "");

    const ip = ALLOW_CLIENT_IP ? (req.body?.ip || getRealIp(req)) : getRealIp(req);

    // sub_id УДАЛЁН по требованию
    const sub_id_2 = req.body?.sub2 || "";

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
    const streamId = info.stream_id || 0;

    const boss_completed = Number(streamId) === Number(ALLOW_STREAM_ID);

    // Если НЕ прошли (boss_completed=false) -> отдаём игровые статы и НЕ отдаём url/streamId и т.п.
    if (!boss_completed) {
      return res.json({
        ok: true,
        boss_completed: false,
        level: 1,
        exp: 15
        // добавляйте любые поля: coins, gems, inventory и т.д.
      });
    }

    // boss_completed=true -> возвращаем как раньше (но поле allow переименовано)
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
      statusCode: response.status || 200,
      boss_completed: true,
      streamId,
      url: finalUrl,
      subId: info.sub_id || "" // это subId из Keitaro (не sub_id из запроса)
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      ok: false,
      boss_completed: false,
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