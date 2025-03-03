const express = require("express");
const { registerUser, login } = require("../controllers/user.controller");
const router = express.Router();

router.post("/register", registerUser);
router.post("/login", login); // Nueva ruta para login

module.exports = router;
