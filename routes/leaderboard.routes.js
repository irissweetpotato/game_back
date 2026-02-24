// routes/leaderboard.routes.js
const express = require("express");
const router = express.Router();

const ctrl = require("../controllers/leaderboard.controller");

// Получить весь лидерборд (отсортирован по score desc)
router.get("/leaderboard", ctrl.getLeaderboard);

// Получить одну запись по guid
router.get("/leaderboard/:guid", ctrl.getEntry);

// Создать запись по guid (если guid уже есть -> 409)
router.post("/leaderboard/:guid", ctrl.createEntry);

// Обновить запись по guid (если нет -> 404)
// PUT - полная замена, PATCH - частичное обновление (в коде ниже PATCH)
router.patch("/leaderboard/:guid", ctrl.updateEntry);

// Удалить запись по guid
router.delete("/leaderboard/:guid", ctrl.deleteEntry);

module.exports = router;