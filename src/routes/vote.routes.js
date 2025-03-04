const express = require("express");
const { vote, hasVoted, countVotes } = require("../controllers/vote.controller");
const { verifyVote } = require("../controllers/vote.controller");
const { authenticateToken } = require("../middlewares/auth"); // Importar autenticación

const router = express.Router();

router.post("/vote", authenticateToken, vote); // Protegido con autenticación
router.get("/has-voted/:voterId", hasVoted);
router.get("/count", countVotes);
// router.post("/vote", vote);
router.post("/verify", verifyVote);

module.exports = router;
