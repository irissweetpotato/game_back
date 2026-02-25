// controllers/leaderboard.controller.js
const svc = require("../services/leaderboard.service");

function isGuidLike(s) {
  return typeof s === "string" && s.length >= 8 && s.length <= 128;
}

function nowSql() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function sanitizePayload(body, allowPartial = true) {
  const out = {};
  if (body == null || typeof body !== "object") return out;

  if ("name" in body) out.name = String(body.name ?? "").slice(0, 64);
  if ("tag" in body) out.tag = String(body.tag ?? "").replace(/^#/, "").slice(0, 16);
  if ("score" in body) out.score = Number(body.score);

  if (!allowPartial) {
    if (!out.name) throw new Error("name is required");
    if (!Number.isFinite(out.score)) throw new Error("score is required and must be number");
  } else {
    if ("score" in out && !Number.isFinite(out.score)) throw new Error("score must be number");
  }

  out.updatedAt = nowSql();
  return out;
}

// GET /leaderboard?page=1&limit=10
exports.getLeaderboard = async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 100);

    const result = await svc.listPaged(page, limit);

    res.set("Cache-Control", "no-store");
    res.status(200).json(result);
  } catch (e) {
    res.status(500).json({
      error: "LEADERBOARD_LIST_FAILED",
      message: String(e?.message || e),
    });
  }
};

exports.getEntry = async (req, res) => {
  try {
    const guid = req.params.guid;
    if (!isGuidLike(guid)) return res.status(400).json({ error: "BAD_GUID" });

    const item = await svc.get(guid);
    if (!item) return res.status(404).json({ error: "NOT_FOUND" });

    res.set("Cache-Control", "no-store");
    res.status(200).json(item);
  } catch (e) {
    res.status(500).json({
      error: "LEADERBOARD_GET_FAILED",
      message: String(e?.message || e),
    });
  }
};

exports.createEntry = async (req, res) => {
  try {
    const guid = req.params.guid;
    if (!isGuidLike(guid)) return res.status(400).json({ error: "BAD_GUID" });

    const payload = sanitizePayload(req.body, false);
    const created = await svc.create(guid, payload);

    res.status(201).json(created);
  } catch (e) {
    if (e && e.code === "ALREADY_EXISTS") return res.status(409).json({ error: "ALREADY_EXISTS" });
    res.status(400).json({ error: "CREATE_FAILED", message: String(e?.message || e) });
  }
};

exports.updateEntry = async (req, res) => {
  try {
    const guid = req.params.guid;
    if (!isGuidLike(guid)) return res.status(400).json({ error: "BAD_GUID" });

    const patch = sanitizePayload(req.body, true);
    const keys = Object.keys(patch).filter((k) => k !== "updatedAt");
    if (keys.length === 0) return res.status(400).json({ error: "EMPTY_PATCH" });

    const updated = await svc.update(guid, patch);
    if (!updated) return res.status(404).json({ error: "NOT_FOUND" });

    res.status(200).json(updated);
  } catch (e) {
    res.status(400).json({ error: "UPDATE_FAILED", message: String(e?.message || e) });
  }
};

exports.deleteEntry = async (req, res) => {
  try {
    const guid = req.params.guid;
    if (!isGuidLike(guid)) return res.status(400).json({ error: "BAD_GUID" });

    const ok = await svc.remove(guid);
    if (!ok) return res.status(404).json({ error: "NOT_FOUND" });

    res.status(204).send();
  } catch (e) {
    res.status(500).json({ error: "DELETE_FAILED", message: String(e?.message || e) });
  }
};