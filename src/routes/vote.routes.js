const express = require("express");
const {
  vote,
  hasVoted,
  countVotes,
  verify,
} = require("../controllers/vote.controller");
const { verifyVote } = require("../controllers/vote.controller");
const { authenticateToken } = require("../middlewares/auth"); // Importar autenticación

const router = express.Router();

router.post("/vote", authenticateToken, vote); // Protegido con autenticación
router.get("/has-voted/:voterId", hasVoted);
router.get("/count", countVotes);
// router.post("/vote", vote);
router.post("/verify", authenticateToken, verifyVote);
router.post("/verifyVote", authenticateToken, verify);

module.exports = router;
