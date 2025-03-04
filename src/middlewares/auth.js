// src/middlewares/auth.js
const jwt = require("jsonwebtoken");
const jwtSecret = process.env.JWT_SECRET; // Asegúrate de definir JWT_SECRET en .env

function authenticateToken(req, res, next) {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(403).json({ error: "Acceso denegado, token requerido" });
  }

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), jwtSecret);
    req.user = decoded; // Guardamos los datos del usuario en req.user
    next();
  } catch (error) {
    res.status(403).json({ error: "Token inválido o expirado" });
  }
}

module.exports = { authenticateToken };
