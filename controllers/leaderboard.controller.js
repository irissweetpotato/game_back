// controllers/leaderboard.controller.js
const { fetchLeaderboard } = require("../services/leaderboard.service");

function normalizeRow(row, idx) {
  return {
    id: row.id ?? idx + 1,
    name: String(row.name ?? row.username ?? "Unknown"),
    tag: String(row.tag ?? "").replace(/^#/, ""),
    score: Number(row.score ?? row.points ?? 0),
    updatedAt: row.updatedAt ?? row.updated_at ?? row.date ?? null,
  };
}

exports.getLeaderboard = async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit || 100), 1000); // защита
    const data = await fetchLeaderboard(limit);

    // Приводим к стабильному формату JSON для фронта
    const list = Array.isArray(data) ? data : [];
    const normalized = list.map(normalizeRow);

    // Гарантируем сортировку (если данные не отсортированы)
    normalized.sort((a, b) => b.score - a.score);

    // Rank не обязателен, фронт может сам — но можно добавить
    const withRank = normalized.map((u, i) => ({ ...u, rank: i + 1 }));

    res.set("Cache-Control", "no-store");
    res.status(200).json(withRank);
  } catch (e) {
    res.status(500).json({ error: "LEADERBOARD_FAILED", message: String(e?.message || e) });
  }
};