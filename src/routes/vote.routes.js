const express = require("express");
const { vote } = require("../controllers/vote.controller");
const { verifyVote } = require("../controllers/vote.controller");
const router = express.Router();

router.post("/vote", vote);
router.post("/verify", verifyVote);


module.exports = router;
