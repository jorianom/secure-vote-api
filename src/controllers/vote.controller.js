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
      .select("id, transaction_id, signature, created_at, r, s, users(document_number, public_key)") // ✅ Agregamos `document_number` desde `users`
      .eq("voter_id", voterId)
      .single();
    if (error && error.code !== "PGRST116") { // PGRST116 = No encontrado en Supabase
      console.error("❌ Error al consultar la base de datos:", error);
      return res.status(500).json({ error: "Error al consultar la base de datos." });
    }
    if (data) {
      let public_base64 = Buffer.from(data.users.public_key).toString('base64')
      return res.json({
        hasVoted: true,
        message: "✅ El usuario ya votó.",
        vote: {
          id: data.id,
          r: data.r,
          s: data.s,
          transaction_id: data.transaction_id,
          public_base64: public_base64,
          signature: data.signature,
          created_at: data.created_at,
          document_number: data.users?.document_number,
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
  const { document_number, candidate, r, s } = req.body;

  try {
    // 1. Obtener la clave pública del usuario
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, public_key")
      .eq("document_number", document_number)
      .single();
    // let candidate = data.candidate
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
    //    Por ejemplo, si en tu DB se guardo r, s junto con el voto
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


const getCandidateName = (candidateId) => {
  const candidates = {
    candidato1: "Gustavo Bolívar",
    candidato2: "María Fernanda Cabal",
    candidato3: "Vicky Dávila",
    candidato4: "Polo Polo",
  };
  return candidates[candidateId] || "Desconocido";
};

// 🔹 Función auxiliar para obtener la imagen del candidato
const getCandidateImage = (candidateId) => {
  const images = {
    candidato1: "/images/1.png",
    candidato2: "/images/2.jpeg",
    candidato3: "/images/3.png",
    candidato4: "/images/4.png",
  };
  return images[candidateId] || "/images/default.png"; // Imagen por defecto si no hay coincidencia
};

exports.verify = async (req, res) => {
  const { r, s, public_base64 } = req.body; // 🔹 Recibe `public_base64`, `r` y `s` del frontend

  try {
    // 1. Decodificar la clave pública desde Base64 a formato PEM
    const publicKeyPem = Buffer.from(public_base64, "base64").toString("utf-8");

    // 2. Buscar el usuario en la base de datos a partir de la clave pública
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, document_number")
      .eq("public_key", publicKeyPem)
      .maybeSingle();

    if (userError) throw new Error(userError.message);
    if (!user) throw new Error("Usuario no encontrado con la clave pública");

    console.log("Usuario encontrado:", user.document_number);

    // 3. Buscar el voto usando `r` y `s` en la base de datos
    const { data: voteData, error: voteError } = await supabase
      .from("votes")
      .select("candidate, r, s")
      .eq("r", r)
      .eq("s", s)
      .maybeSingle();

    if (voteError) throw new Error(voteError.message);
    if (!voteData) {
      return res.json({
        valid: false,
        message: "Voto no encontrado o datos de firma incorrectos",
      });
    }

    // 4. Extraer el candidato del voto encontrado
    const candidate = voteData.candidate;

    // 5. Reconstruir la firma DER a partir de r y s
    const derSignature = encodeSignature(r, s);

    // 6. Configurar la verificación con SHA256
    const verify = crypto.createVerify("SHA256");
    verify.update(candidate);
    verify.end();

    // 7. Crear un objeto de clave pública con la clave decodificada
    const publicKeyObj = crypto.createPublicKey({
      key: publicKeyPem,
      format: "pem",
      type: "spki",
    });

    // 8. Verificar la firma
    const isSignatureValid = verify.verify(publicKeyObj, derSignature);

    return res.json({
      valid: isSignatureValid,
      message: isSignatureValid
        ? "Voto verificado correctamente"
        : "Firma inválida",
    });
  } catch (error) {
    console.error("Error en /verify-vote:", error);
    return res.status(500).json({ error: error.message, valid: false });
  }
};