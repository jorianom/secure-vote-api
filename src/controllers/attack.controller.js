// controllers/attack.controller.js

const supabase = require("../config/supabase");
const crypto = require("crypto");

// Debe ser la misma clave secreta utilizada en user.controller.js y vote.controller.js
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");

// Función para descifrar la clave privada
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
  return decrypted.toString("utf8");
}

/**
 * Endpoint de ataque (ejemplo educativo).
 * "attacker_document_number" es el documento del atacante (para ver cómo fallará si no tienen su propia private key),
 * "victim_document_number" es el documento de la víctima cuyas credenciales se suplantarán.
 * "candidate" es el candidato por el que el atacante quiere votar en lugar de la víctima.
 */
exports.impostorVote = async (req, res) => {
  try {
    const { attacker_document_number, victim_document_number, candidate } =
      req.body;

    // 1) Consultar al "atacante" en la BD (para ver su propia info)
    const { data: attackerData, error: attackerError } = await supabase
      .from("users")
      .select("*")
      .eq("document_number", attacker_document_number)
      .single();

    if (attackerError || !attackerData) {
      return res
        .status(404)
        .json({ error: "Atacante no encontrado en la base de datos" });
    }

    // 2) Consultar a la "víctima" (cuyos datos se desea suplantar)
    const { data: victimData, error: victimError } = await supabase
      .from("users")
      .select("*")
      .eq("document_number", victim_document_number)
      .single();

    if (victimError || !victimData) {
      return res
        .status(404)
        .json({ error: "Víctima no encontrada en la base de datos" });
    }

    // 3) Descifrar la clave privada de la víctima
    const victimDecryptedPrivateKey = decrypt(victimData.private_key);

    // 4) Usar la clave privada de la víctima para firmar el voto
    const sign = crypto.createSign("SHA256");
    sign.update(candidate);
    sign.end();

    const privateKeyObj = crypto.createPrivateKey({
      key: victimDecryptedPrivateKey,
      format: "pem",
      type: "pkcs8",
    });

    const signature = sign.sign(privateKeyObj, "hex");

    // 5) Insertar el "voto suplantado"
    const { data: insertedVote, error: voteError } = await supabase
      .from("votes")
      .insert([{ voter_id: victimData.id, candidate, signature }]);

    if (voteError) throw voteError;

    return res.json({
      message: "Ataque de suplantación realizado (ejemplo educativo)",
      insertedVote,
      signature,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
