// src/controllers/vote.controller.js

const supabase = require("../config/supabase");
const crypto = require("crypto");

// Leemos SECRET_KEY (asegúrate de haber hecho require('dotenv').config() en tu index.js)
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");

// Map para bloquear llamadas concurrentes por documento (opcional)
const voteLocks = new Map();

/**
 * Descifra la clave privada usando AES-256-GCM
 */
function decrypt(encryptedData) {
  const parsed = JSON.parse(encryptedData);
  const iv = Buffer.from(parsed.iv, "hex");
  const tag = Buffer.from(parsed.tag, "hex");
  const encryptedText = Buffer.from(parsed.encrypted, "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", secretKey, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final(),
  ]);
  return decrypted.toString("utf8"); // Devuelve la clave privada en formato PEM
}

/**
 * Endpoint para emitir un voto.
 * Permite UN SOLO voto por usuario (valida en la tabla 'votes' que no exista uno previo).
 */
exports.vote = async (req, res) => {
  const { userId, candidate } = req.body;

  // Validación rápida de campos
  if (!userId || !candidate) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  // Bloquear solicitudes concurrentes para el mismo userId
  if (voteLocks.has(userId)) {
    return res
      .status(429)
      .json({ error: "Voto en proceso. Intente nuevamente." });
  }
  voteLocks.set(userId, true);

  try {
    // 1. Obtener el usuario por documento
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("id", userId)
      .single(); // single() -> Lanza error si no hay registros

    if (userError || !user) {
      throw new Error("Usuario no encontrado");
    }

    // 2. Verificar si ya existe un voto del usuario
    const { data: existingVote, error: existingVoteError } = await supabase
      .from("votes")
      .select("id") // solo necesitamos el id para saber si hay voto
      .eq("voter_id", user.id)
      .maybeSingle();
    // maybeSingle() -> no lanza error si no encuentra filas, solo retorna null

    if (existingVoteError) {
      // Si hay un error que NO sea simplemente "no encontró filas", lo lanzamos
      throw existingVoteError;
    }

    // Si existingVote NO es null, entonces sí hay voto previo
    if (existingVote) {
      throw new Error("El usuario ya ha votado");
    }

    // 3. Descifrar la clave privada y firmar el voto
    const decryptedPrivateKey = decrypt(user.private_key);

    const sign = crypto.createSign("SHA256");
    sign.update(candidate);
    sign.end();

    const privateKeyObj = crypto.createPrivateKey({
      key: decryptedPrivateKey,
      format: "pem",
      type: "pkcs8",
    });

    const signature = sign.sign(privateKeyObj, "hex");

    // 4. Insertar el voto en la tabla 'votes'
    const { error: insertVoteError } = await supabase.from("votes").insert([
      {
        voter_id: user.id,
        candidate: candidate,
        signature: signature,
        created_at: new Date().toISOString(),
      },
    ]);

    if (insertVoteError) {
      // Podría ser un error de clave duplicada u otro
      throw insertVoteError;
    }

    // 5. Responder OK
    res.json({
      message: "Voto registrado exitosamente",
      candidate,
      signature,
    });
  } catch (error) {
    // Controlamos mensajes de error
    res.status(400).json({
      error:
        error.message.includes("duplicate key") ||
          error.message.includes("ya existe")
          ? "Voto duplicado detectado"
          : error.message,
    });
  } finally {
    // Liberar el bloqueo
    voteLocks.delete(userId);
  }
};

exports.hasVoted = async (req, res) => {
  const { voterId } = req.params;

  try {
    // 🔹 Buscar si el usuario ya ha votado y traer más datos del voto
    const { data, error } = await supabase
      .from("votes")
      .select("id, candidate, signature, created_at") // ✅ Agregamos más columnas
      .eq("voter_id", voterId)
      .single();

    if (error && error.code !== "PGRST116") { // PGRST116 = No encontrado en Supabase
      console.error("❌ Error al consultar la base de datos:", error);
      return res.status(500).json({ error: "Error al consultar la base de datos." });
    }

    if (data) {
      return res.json({
        hasVoted: true,
        message: "✅ El usuario ya votó.",
        vote: {
          id: data.id,
          candidate: data.candidate,
          signature: data.signature,
          created_at: data.created_at,
        },
      });
    } else {
      return res.json({ hasVoted: false, message: "⚠️ El usuario aún no ha votado." });
    }
  } catch (err) {
    console.error("❌ Error en /has-voted:", err);
    res.status(500).json({ error: "Error interno del servidor." });
  }
};


exports.verifyVote = async (req, res) => {
  const { document_number, candidate, signature } = req.body;

  try {
    // 1. Obtener la clave pública según el document_number
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, public_key")
      .eq("document_number", document_number)
      .single();

    if (userError || !user) {
      throw new Error("Usuario no encontrado");
    }

    // 2. Verificar la firma
    const verify = crypto.createVerify("SHA256");
    verify.update(candidate);
    verify.end();

    const publicKeyObj = crypto.createPublicKey({
      key: user.public_key,
      format: "pem",
      type: "spki",
    });

    const isSignatureValid = verify.verify(publicKeyObj, signature, "hex");

    // 3. Verificar concordancia con la BD (que esa signature exista para voter_id)
    const { data: storedVote, error: storedVoteError } = await supabase
      .from("votes")
      .select("*")
      .eq("voter_id", user.id)
      .eq("signature", signature)
      .maybeSingle();

    if (storedVoteError) {
      throw storedVoteError;
    }

    const isVoteFound = !!storedVote;

    res.json({
      valid: isSignatureValid && isVoteFound,
      message:
        isSignatureValid && isVoteFound
          ? "Voto verificado correctamente"
          : "Firma inválida o voto no registrado",
    });
  } catch (error) {
    res.status(500).json({ error: error.message, valid: false });
  }
};


exports.countVotes = async (req, res) => {
  try {
    // 🔹 Obtener todos los votos
    const { data, error } = await supabase
      .from("votes")
      .select("candidate");

    if (error) {
      console.error("❌ Error consultando votos:", error);
      return res.status(500).json({ error: "Error al contar los votos." });
    }

    // 🔹 Contar los votos manualmente agrupando por candidato
    const voteCount = data.reduce((acc, vote) => {
      acc[vote.candidate] = (acc[vote.candidate] || 0) + 1;
      return acc;
    }, {});

    // 🔹 Formatear la respuesta con nombres e imágenes
    const formattedData = Object.entries(voteCount).map(([candidate, votes]) => ({
      id: candidate,
      name: getCandidateName(candidate),
      image: getCandidateImage(candidate),
      votes,
    }));

    res.json(formattedData);
  } catch (err) {
    console.error("❌ Error interno en /count-votes:", err);
    res.status(500).json({ error: "Error interno del servidor." });
  }
};

// 🔹 Función auxiliar para asignar nombres a los candidatos
const getCandidateName = (candidateId) => {
  const candidates = {
    candidato1: "María García",
    candidato2: "Carlos Rodríguez",
    candidato3: "Ana Fernández",
    candidato4: "Luis Martínez",
  };
  return candidates[candidateId] || "Desconocido";
};

// 🔹 Función auxiliar para asignar imágenes a los candidatos
const getCandidateImage = (candidateId) => {
  return `https://picsum.photos/200/200?random=${candidateId}`;
};
