// auth.js
export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname || "";
  const DB = env.DB;

  // Helper: hash password using SubtleCrypto
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // Helper: generate recovery code (8 chars, alphanumeric uppercase)
  function generateRecoveryCode(length = 8) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "";
    for (let i = 0; i < length; i++) {
      out += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return out;
  }

  // Parse JSON body safely
  let data;
  try {
    data = await request.json();
  } catch (err) {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const method = request.method.toUpperCase();

  // Only POST handled here (worker route mapped to /api/auth)
  if (!path.endsWith("/signup") && !path.endsWith("/login") && !path.endsWith("/reset")) {
    return new Response(JSON.stringify({ error: "Invalid endpoint" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  // ---------- SIGNUP ----------
  if (path.endsWith("/signup")) {
    const { name, email, password } = data || {};
    // validations
    if (!name || !email || !password) {
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(name).trim().length < 5) {
      return new Response(JSON.stringify({ error: "Name must be at least 5 characters" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(password).length < 8) {
      return new Response(JSON.stringify({ error: "Password must be at least 8 characters" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // check existing
    const existing = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (existing) {
      return new Response(JSON.stringify({ error: "User already exists" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      });
    }

    const hashed = await hashPassword(password);
    const recovery_code = generateRecoveryCode(8);

    // Insert user including recovery_code
    await DB.prepare(
      "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
    )
      .bind(name, email, hashed, null, null, recovery_code)
      .run();

    // fetch inserted user (without password)
    const user = await DB.prepare("SELECT id, name, email, phone, gender FROM users WHERE email = ?")
      .bind(email)
      .first();

    return new Response(
      JSON.stringify({
        message: "Signup successful",
        recovery_code,
        user,
      }),
      { status: 201, headers: { "Content-Type": "application/json" } }
    );
  }

  // ---------- LOGIN ----------
  if (path.endsWith("/login")) {
    const { email, password } = data || {};
    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const dbUser = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!dbUser) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    const hashed = await hashPassword(password);
    if (hashed !== dbUser.password) {
      return new Response(JSON.stringify({ error: "Incorrect password" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // return user data without password/recovery code
    const { id, name, phone, gender } = dbUser;
    const user = { id, name, email, phone, gender };

    return new Response(JSON.stringify({ message: "Login successful", user }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  // ---------- RESET (use recovery code) ----------
  if (path.endsWith("/reset")) {
    const { email, recovery_code, new_password } = data || {};
    if (!email || !recovery_code || !new_password) {
      return new Response(JSON.stringify({ error: "Missing email, recovery_code or new_password" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(new_password).length < 8) {
      return new Response(JSON.stringify({ error: "New password must be at least 8 characters" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const dbUser = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!dbUser) {
      return new Response(JSON.stringify({ error: "User not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (dbUser.recovery_code !== recovery_code) {
      return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // update password (hash) and create new recovery code (expire old)
    const hashed = await hashPassword(new_password);
    const newRecovery = generateRecoveryCode(8);

    await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE email = ?")
      .bind(hashed, newRecovery, email)
      .run();

    return new Response(JSON.stringify({ message: "Password reset successful", recovery_code: newRecovery }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  // fallback
  return new Response(JSON.stringify({ error: "Unhandled endpoint" }), {
    status: 404,
    headers: { "Content-Type": "application/json" },
  });
}
