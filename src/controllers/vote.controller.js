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
  const { document_number, candidate } = req.body;

  // Validación rápida de campos
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
    voteLocks.delete(document_number);
  }
};

/**
 * Endpoint para verificar un voto.
 * Se revisa la firma con la clave pública, y se verifica que
 * efectivamente ese signature esté en la BD con la combinación (voter_id, signature).
 */
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
