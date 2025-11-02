export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;
  const DB = env.DB;

  // === Helper: Hash password with SHA-256 ===
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // === Helper: Generate recovery code ===
  function generateRecoveryCode() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  }

  const data = await request.json();
  const { name, email, password, phone, gender, recovery_code, new_password } = data;

  // === SIGNUP ===
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
    const code = generateRecoveryCode();

    await DB.prepare(
      "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(name, email, hashed, phone || null, gender || null, code).run();

    return new Response(JSON.stringify({
      message: "Signup successful",
      recovery_code: code,
      note: "Please save this recovery code carefully! It will be shown only once."
    }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // === LOGIN ===
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

  // === PASSWORD RESET ===
  if (path.endsWith("/reset")) {
    if (!email || !recovery_code || !new_password) {
      return new Response(JSON.stringify({ error: "Missing fields" }), {
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

    if (recovery_code !== user.recovery_code) {
      return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
        headers: { "Content-Type": "application/json" },
        status: 403,
      });
    }

    const hashed = await hashPassword(new_password);
    const newCode = generateRecoveryCode();

    await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE email = ?")
      .bind(hashed, newCode, email)
      .run();

    return new Response(JSON.stringify({
      message: "Password reset successful",
      new_recovery_code: newCode,
      note: "Save this new recovery code — your old one is now expired."
    }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ error: "Invalid endpoint" }), {
    headers: { "Content-Type": "application/json" },
    status: 404,
  });
}
