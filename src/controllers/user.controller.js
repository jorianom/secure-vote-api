const supabase = require("../config/supabase");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// SECRET_KEY para JWT (asegúrate de definirla en .env)
const jwtSecret = process.env.JWT_SECRET;

// La clave secreta de 32 bytes (256 bits) en formato hexadecimal (para cifrar la clave privada)
const secretKey = Buffer.from(process.env.SECRET_KEY, "hex");

// Función para cifrar la clave privada usando AES-256-GCM
function encrypt(text) {
  const iv = crypto.randomBytes(12); // IV recomendado para AES-GCM (12 bytes)
  const cipher = crypto.createCipheriv("aes-256-gcm", secretKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    encrypted: encrypted.toString("hex"),
  };
}

// Registrar un nuevo votante
exports.registerUser = async (req, res) => {
  console.log("registerUser");

  // Esperamos 'password' además de los demás campos
  const { name, document_type, document_number, password } = req.body;

  // Validar que todos los campos requeridos estén presentes
  if (!name || !document_type || !document_number || !password) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  try {
    // Hashear la contraseña con bcrypt
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generar clave pública y privada DSA
    const { privateKey, publicKey } = crypto.generateKeyPairSync("dsa", {
      modulusLength: 2048,
    });

    // Exportar claves en formato PEM
    const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
    const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });

    // Cifrar la clave privada antes de almacenarla
    const encryptedPrivateKey = JSON.stringify(encrypt(privateKeyPem));

    // Insertar usuario en Supabase
    const { data, error } = await supabase
      .from("users")
      .insert([
        {
          name,
          document_type,
          document_number,
          public_key: publicKeyPem,
          private_key: encryptedPrivateKey,
          password: hashedPassword, // Guardamos la contraseña hasheada
        },
      ])
      .select();

    if (error) throw error;

    res.json({ message: "Votante registrado", user: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.login = async (req, res) => {
  const { document_number, document_type, password } = req.body;

  // Validar que se ingresaron los 3 campos
  if (!document_number || !document_type || !password) {
    return res.status(400).json({ error: "Datos incompletos" });
  }

  try {
    // 1. Buscar al usuario que coincida con document_number y document_type
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, name, document_type, password")
      .eq("document_number", document_number)
      .eq("document_type", document_type)
      .single();

    // Si no existe o hay error, retornamos que las credenciales son incorrectas
    if (userError || !user) {
      return res
        .status(401)
        .json({ error: "Usuario o contraseña incorrectos" });
    }

    // 2. Comparar la contraseña ingresada con la almacenada (bcrypt)
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res
        .status(401)
        .json({ error: "Usuario o contraseña incorrectos" });
    }

    // 3. Generar un token JWT
    const token = jwt.sign(
      { userId: user.id, document_number },
      jwtSecret,
      { expiresIn: "1h" } // Expira en 1 hora
    );

    // 4. Devolver token, ID y nombre del usuario
    res.json({
      message: "Inicio de sesión exitoso",
      token,
      user: {
        id: user.id,
        name: user.name,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
