const express = require("express");
const { vote } = require("../controllers/vote.controller");
const { verifyVote } = require("../controllers/vote.controller");
const { authenticateToken } = require("../middlewares/auth"); // Importar autenticación

const router = express.Router();

router.post("/vote", authenticateToken, vote); // Protegido con autenticación
router.post("/verify", verifyVote);

module.exports = router;
