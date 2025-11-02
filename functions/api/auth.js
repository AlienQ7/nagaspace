export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;
  const DB = env.DB;

  // --- Helpers ---
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function generateRecoveryCode() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let code = "";
    for (let i = 0; i < 12; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
  }

  const data = await request.json();
  const { name, email, password, phone, gender } = data;

  // --- SIGNUP ---
  if (path.endsWith("/signup")) {
    if (!email || !password || !name) {
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const existing = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (existing) {
      return new Response(JSON.stringify({ error: "User already exists" }), {
        headers: { "Content-Type": "application/json" },
        status: 409,
      });
    }

    const hashed = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();

    await DB.prepare(
      "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(name, email, hashed, phone || null, gender || null, recoveryCode).run();

    return new Response(JSON.stringify({ 
      message: "Signup successful",
      recovery_code: recoveryCode 
    }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // --- LOGIN ---
  if (path.endsWith("/login")) {
    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });
    }

    const hashed = await hashPassword(password);
    if (hashed !== user.password) {
      return new Response(JSON.stringify({ error: "Incorrect password" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });
    }

    delete user.password;
    return new Response(JSON.stringify({ message: "Login successful", user }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ error: "Invalid endpoint" }), {
    headers: { "Content-Type": "application/json" },
    status: 404,
  });
}
