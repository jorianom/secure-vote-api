const supabase = require("../config/supabase");
const crypto = require("crypto");

// Registrar un voto con firma DSA
exports.vote = async (req, res) => {
    const { document_number, candidate } = req.body;

    try {
        // Obtener usuario por documento
        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .eq("document_number", document_number)
            .single();

        if (error || !user) return res.status(404).json({ error: "Usuario no encontrado" });

        // Firmar el voto con DSA
        const sign = crypto.createSign("SHA256");
        sign.update(candidate);
        sign.end();

        const privateKey = crypto.createPrivateKey({
            key: user.private_key,
            format: "pem",
            type: "pkcs8"
        });

        const signature = sign.sign(privateKey, "hex");

        // Insertar el voto en Supabase
        const { data, error: voteError } = await supabase
            .from("votes")
            .insert([{ voter_id: user.id, candidate, signature }]);

        if (voteError) throw voteError;

        res.json({ message: "Voto registrado", signature });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};


exports.verifyVote = async (req, res) => {
    const { document_number, candidate, signature } = req.body;

    try {
        // Obtener la clave pública del usuario en Supabase
        const { data: user, error } = await supabase
            .from("users")
            .select("public_key")
            .eq("document_number", document_number)
            .single();

        if (error || !user) return res.status(404).json({ error: "Usuario no encontrado" });

        // Verificar la firma con la clave pública
        const verify = crypto.createVerify("SHA256");
        verify.update(candidate);
        verify.end();

        const publicKey = crypto.createPublicKey({
            key: user.public_key,
            format: "pem",
            type: "spki"
        });

        const isValid = verify.verify(publicKey, signature, "hex");

        res.json({
            message: isValid ? "Firma válida" : "Firma inválida",
            isValid
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};