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
        if (error && error.code !== "PGRST116") { // PGRST116 = No encontrado en Supabase
            return res.status(500).json({ error: "Error al consultar la base de datos." });
        }

        if (data) {
            return res.json({ hasVoted: true, message: "El usuario ya votó." });
        } else {
            return res.json({ hasVoted: false, message: "El usuario aún no ha votado." });
        }
    } catch (err) {
        console.error("Error en /has-voted:", err);
        res.status(500).json({ error: "Error interno del servidor." });
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