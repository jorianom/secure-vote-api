const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// Rutas
app.use("/api/users", require("./routes/user.routes"));
app.use("/api/votes", require("./routes/vote.routes"));
app.use("/api/attacks", require("./routes/attack.routes"));

// Iniciar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
