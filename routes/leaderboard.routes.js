// routes/leaderboard.routes.js
const express = require("express");
const router = express.Router();

const { getLeaderboard } = require("../controllers/leaderboard.controller");

router.get("/leaderboard", getLeaderboard);

module.exports = router;