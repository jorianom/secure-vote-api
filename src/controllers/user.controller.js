const supabase = require("../config/supabase");

// Registrar un nuevo votante
exports.registerUser = async (req, res) => {
    console.log("registerUser");
    const { name, document_type, document_number } = req.body;

    // Generar clave pública y privada DSA
    const { privateKey, publicKey } = require("crypto").generateKeyPairSync("dsa", {
        modulusLength: 2048
    });

    try {
        // Insertar usuario en Supabase
        const { data, error } = await supabase
            .from("users")
            .insert([{
                name, document_type, document_number, public_key: publicKey.export({ format: "pem", type: "spki" })
                , private_key: privateKey.export({ format: "pem", type: "pkcs8" })
            }]).select();

        if (error) throw error;

        res.json({ message: "Votante registrado", user: data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
