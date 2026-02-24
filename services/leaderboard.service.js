// services/leaderboard.service.js
const fs = require("fs/promises");
const path = require("path");

const DATA_PATH = path.join(__dirname, "..", "data", "leaderboard.json");

exports.fetchLeaderboard = async (limit = 100) => {
  const raw = await fs.readFile(DATA_PATH, "utf-8");
  const json = JSON.parse(raw);

  if (!Array.isArray(json)) return [];
  return json.slice(0, limit);
};