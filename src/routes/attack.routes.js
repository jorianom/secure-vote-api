// routes/attack.routes.js
const express = require("express");
const { impostorVote } = require("../controllers/attack.controller");
const router = express.Router();

router.post("/impostor", impostorVote);

module.exports = router;
