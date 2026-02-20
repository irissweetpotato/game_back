require("dotenv").config();
const express = require("express");
const axios = require("axios");
const https = require("https");

const app = express();
app.use(express.json({ limit: "256kb" }));

// Если позже поставите nginx / cloudflare, это позволит Express корректно читать req.ip из X-Forwarded-For
app.set("trust proxy", true);

// ===== НАСТРОЙКИ =====
const KEITARO_TRACKER = process.env.KEITARO_TRACKER || "";
const KEITARO_TOKEN = process.env.KEITARO_TOKEN || "";
const ALLOW_STREAM_ID = Number(process.env.ALLOW_STREAM_ID || 0);
const API_KEY = process.env.API_KEY || "";

// Опционально: если у Keitaro самоподписанный сертификат, можно временно отключить проверку TLS.
// НЕ рекомендуется для продакшна.
const INSECURE_SSL = String(process.env.INSECURE_SSL || "").toLowerCase() === "1";
const httpsAgent = INSECURE_SSL ? new https.Agent({ rejectUnauthorized: false }) : undefined;

// Опционально: если вам прям надо разрешить подставной IP из клиента (для тестов) — включите.
// По умолчанию IP берётся из реального запроса.
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

// Реальный IP (а не из тела запроса)
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

function toAbsoluteUrl(maybeRelative, baseUrl) {
  try {
    return new URL(maybeRelative, baseUrl).toString();
  } catch {
    return maybeRelative || "";
  }
}

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/keitaro_gate", auth, async (req, res) => {
  try {
    if (!KEITARO_TRACKER || !KEITARO_TOKEN || !ALLOW_STREAM_ID) {
      throw new Error("Server not configured");
    }

    // UA / language лучше брать из заголовков (так же, как IP)
    // но оставляем обратную совместимость: если клиент прислал в body — используем как fallback
    const ua = (req.headers["user-agent"] && String(req.headers["user-agent"])) || (req.body?.ua || "");
    const language = getLanguage(req) || (req.body?.language || "");

    // IP: по умолчанию только реальный IP запроса; body.ip игнорируется
    const ip = ALLOW_CLIENT_IP ? (req.body?.ip || getRealIp(req)) : getRealIp(req);

    // ваши sub-параметры (как было)
    const sub_id = req.body?.sub_id || "";
    const sub_id_2 = req.body?.sub2 || "";

    // 1) Запрос к Click API
    const clickApiUrl =
      `${KEITARO_TRACKER}/click_api/v3` +
      `?token=${encodeURIComponent(KEITARO_TOKEN)}` +
      `&info=1&log=0` +
      (ip ? `&ip=${encodeURIComponent(ip)}` : "") +
      (ua ? `&user_agent=${encodeURIComponent(ua)}` : "") +
      (language ? `&language=${encodeURIComponent(language)}` : "") +
      (sub_id ? `&sub_id=${encodeURIComponent(sub_id)}` : "") +
      (sub_id_2 ? `&sub_id_2=${encodeURIComponent(sub_id_2)}` : "");

    const response = await axios.get(clickApiUrl, {
      timeout: 8000,
      validateStatus: () => true,
      ...(httpsAgent ? { httpsAgent } : {})
    });

    const data = response.data || {};
    const info = data.info || {};
    const streamId = info.stream_id || 0;

    // 2) Пытаемся взять Location из JSON Click API
    const clickApiLocation = pickHeader(data.headers, "Location");

    // 3) Если Location нет — берём token и “разворачиваем” редирект через /?_lp=1&_token=...
    let finalUrl = "";

    if (clickApiLocation) {
      finalUrl = clickApiLocation;
    } else if (info.token) {
      const lpUrl = `${KEITARO_TRACKER}/?_lp=1&_token=${encodeURIComponent(info.token)}`;

      // Делаем запрос и НЕ идём по редиректам, чтобы взять Location из HTTP-ответа
      const rr = await axios.get(lpUrl, {
        timeout: 8000,
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
        ...(httpsAgent ? { httpsAgent } : {})
      });

      const httpLocation = rr.headers && rr.headers["location"] ? String(rr.headers["location"]) : "";

      // Если Location относительный — делаем абсолютным
      finalUrl = httpLocation ? toAbsoluteUrl(httpLocation, lpUrl) : lpUrl;
    } else {
      finalUrl = "";
    }

    const allow = Number(streamId) === Number(ALLOW_STREAM_ID);

    res.json({
      ok: true,
      statusCode: response.status || 200,
      allow,
      streamId,
      url: finalUrl,
      subId: info.sub_id || ""
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      ok: false,
      allow: false,
      streamId: 0,
      url: "",
      error: String(err?.message || err)
    });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
