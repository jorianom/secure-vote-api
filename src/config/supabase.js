require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

// Conectar a Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

module.exports = supabase;
