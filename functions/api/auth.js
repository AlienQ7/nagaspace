export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;
  const DB = env.DB;

  // helper: hash password using subtle crypto
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // helper: generate random recovery code
  function generateRecoveryCode() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let code = "";
    for (let i = 0; i < 10; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
    return code;
  }

  const data = await request.json();

  // ========== SIGNUP ==========
  if (path.endsWith("/signup")) {
    const { name, email, password } = data;
    if (!email || !password || !name)
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });

    const existing = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (existing)
      return new Response(JSON.stringify({ error: "User already exists" }), {
        headers: { "Content-Type": "application/json" },
        status: 409,
      });

    const hashed = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();

    await DB.prepare(
      "INSERT INTO users (name, email, password, recovery_code) VALUES (?, ?, ?, ?)"
    ).bind(name, email, hashed, recoveryCode).run();

    return new Response(JSON.stringify({ message: "Signup successful", recovery_code: recoveryCode }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // ========== LOGIN ==========
  if (path.endsWith("/login")) {
    const { email, password } = data;
    if (!email || !password)
      return new Response(JSON.stringify({ error: "Missing fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });

    const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user)
      return new Response(JSON.stringify({ error: "User not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });

    const hashed = await hashPassword(password);
    if (hashed !== user.password)
      return new Response(JSON.stringify({ error: "Incorrect password" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });

    delete user.password;
    return new Response(JSON.stringify({ message: "Login successful", user }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // ========== FORGOT PASSWORD ==========
  if (path.endsWith("/forgot-password")) {
    const { email, recovery_code, new_password } = data;
    if (!email || !recovery_code || !new_password)
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });

    const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user)
      return new Response(JSON.stringify({ error: "User not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });

    if (user.recovery_code !== recovery_code)
      return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
        headers: { "Content-Type": "application/json" },
        status: 401,
      });

    const newHashed = await hashPassword(new_password);
    const newRecoveryCode = generateRecoveryCode();

    await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE email = ?")
      .bind(newHashed, newRecoveryCode, email)
      .run();

    return new Response(JSON.stringify({
      message: "Password reset successful",
      new_recovery_code: newRecoveryCode,
    }), { headers: { "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ error: "Invalid endpoint" }), {
    headers: { "Content-Type": "application/json" },
    status: 404,
  });
}
