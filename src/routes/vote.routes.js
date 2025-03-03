const express = require("express");
const { vote, hasVoted, countVotes } = require("../controllers/vote.controller");
const { verifyVote } = require("../controllers/vote.controller");
const router = express.Router();

router.get("/has-voted/:voterId", hasVoted);
router.get("/count", countVotes);
router.post("/vote", vote);
router.post("/verify", verifyVote);


module.exports = router;
