// src/controllers/vote.controller.js

const supabase = require("../config/supabase");
const crypto = require("crypto");
const asn1 = require("asn1.js");

// Leemos SECRET_KEY (asegúrate de haber hecho require('dotenv').config() en tu index.js)
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");

// Map para bloquear llamadas concurrentes por documento (opcional)
const voteLocks = new Map();

const DSASignature = asn1.define("DSASignature", function () {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

function encodeSignature(rHex, sHex) {
  // rHex y sHex son strings en hex
  const BN = require("bn.js"); // Librería para big numbers (asn1.js la usa internamente)
  const rBN = new BN(rHex, 16);
  const sBN = new BN(sHex, 16);

  // Usamos DSASignature.encode para crear el DER
  return DSASignature.encode({ r: rBN, s: sBN }, "der");
}

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
  const { document_number, candidate } = req.body;

  if (!document_number || !candidate) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  // Bloquear solicitudes concurrentes para el mismo document_number
  if (voteLocks.has(document_number)) {
    return res
      .status(429)
      .json({ error: "Voto en proceso. Intente nuevamente." });
  }
  voteLocks.set(document_number, true);

  try {
    // 1. Obtener el usuario por documento
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("document_number", document_number)
      .single();

    if (userError || !user) {
      throw new Error("Usuario no encontrado");
    }

    // 2. Verificar si ya existe un voto del usuario
    const { data: existingVote, error: existingVoteError } = await supabase
      .from("votes")
      .select("id")
      .eq("voter_id", user.id)
      .maybeSingle();

    if (existingVoteError) {
      throw existingVoteError;
    }

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

    // Firma en formato DER (Buffer)
    const signatureBuffer = sign.sign(privateKeyObj);

    // Convertir la firma a hex para guardarla en la BD
    const signatureHex = signatureBuffer.toString("hex");

    // EXTRAER r, s de la firma DER (opcional, si deseas exponerlos)
    const { r, s } = DSASignature.decode(signatureBuffer, "der");

    // 4. Generar un transaction_id robusto (32 hex chars)
    const transactionId = crypto.randomBytes(16).toString("hex");

    // 5. Insertar el voto en la tabla 'votes'
    const { error: insertVoteError } = await supabase.from("votes").insert([
      {
        voter_id: user.id,
        candidate: candidate,
        signature: signatureHex,
        transaction_id: transactionId,
        created_at: new Date().toISOString(),
        r: r,
        s: s,
      },
    ]);

    if (insertVoteError) {
      throw insertVoteError;
    }

    // 6. Responder OK (incluyendo transaction_id, r, s)
    res.json({
      message: "Voto registrado exitosamente",
      candidate,
      signature: signatureHex,
      transaction_id: transactionId,
      r: r.toString(16),
      s: s.toString(16),
    });
  } catch (error) {
    res.status(400).json({
      error:
        error.message.includes("duplicate key") ||
        error.message.includes("ya existe")
          ? "Voto duplicado detectado"
          : error.message,
    });
  } finally {
    voteLocks.delete(document_number);
  }
};

exports.hasVoted = async (req, res) => {
  const { voterId } = req.params;

  try {
    // Buscar si el usuario ya tiene un voto registrado
    const { data, error } = await supabase
      .from("votes")
      .select("id")
      .eq("voter_id", voterId)
      .single();
    console.log("data", data);
    console.log("error", error);
    if (error && error.code !== "PGRST116") {
      // PGRST116 = No encontrado en Supabase
      return res
        .status(500)
        .json({ error: "Error al consultar la base de datos." });
    }

    if (data) {
      return res.json({ hasVoted: true, message: "El usuario ya votó." });
    } else {
      return res.json({
        hasVoted: false,
        message: "El usuario aún no ha votado.",
      });
    }
  } catch (err) {
    console.error("Error en /has-voted:", err);
    res.status(500).json({ error: "Error interno del servidor." });
  }
};

exports.verifyVote = async (req, res) => {
  const { document_number, candidate, r, s } = req.body;

  try {
    // 1. Obtener la clave pública del usuario
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, public_key")
      .eq("document_number", document_number)
      .single();

    if (userError || !user) {
      throw new Error("Usuario no encontrado");
    }

    // 2. Reconstruir la firma DER a partir de r, s
    const derSignature = encodeSignature(r, s);

    // 3. Configurar verificación con SHA256
    const verify = crypto.createVerify("SHA256");
    verify.update(candidate);
    verify.end();

    const publicKeyObj = crypto.createPublicKey({
      key: user.public_key,
      format: "pem",
      type: "spki",
    });

    // 4. Verificar la firma DER
    const isSignatureValid = verify.verify(publicKeyObj, derSignature);

    // 5. (Opcional) Verificar que r, s correspondan a un voto guardado
    //    Por ejemplo, si en tu DB guardaste r, s junto con el voto
    const { data: storedVote, error: storedVoteError } = await supabase
      .from("votes")
      .select("*")
      .eq("voter_id", user.id)
      .eq("r", r) // si tienes columna r
      .eq("s", s) // si tienes columna s
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
    const { data, error } = await supabase.from("votes").select("candidate");

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
    const formattedData = Object.entries(voteCount).map(
      ([candidate, votes]) => ({
        id: candidate,
        name: getCandidateName(candidate),
        image: getCandidateImage(candidate),
        votes,
      })
    );

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
