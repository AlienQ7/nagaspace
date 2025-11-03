// functions/api/auth.js

export async function onRequestPost(context) {
  const { request, env } = context;
  const DB = env.DB; // D1 binding

  // --- Helper: SHA-256 password hash ---
  async function hashPassword(password) {
    const enc = new TextEncoder();
    const data = enc.encode(password);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // --- Helper: Recovery Code Generator ---
  function makeRecoveryCode(len = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    const rand = crypto.getRandomValues;
    while (out.length < len) {
      const r = new Uint32Array(1);
      rand(r);
      let v = r[0];
      while (v && out.length < len) {
        out += chars[v % chars.length];
        v = Math.floor(v / chars.length);
      }
    }
    return out;
  }

  // --- Parse JSON safely ---
  let body = {};
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: "Invalid or missing JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // --- Detect action (signup / login / forgot) ---
  const url = new URL(request.url);
  const pathname = url.pathname || "";
  let action = (body.action || "").toString().toLowerCase();
  if (!action) {
    if (pathname.endsWith("/signup")) action = "signup";
    else if (pathname.endsWith("/login")) action = "login";
    else if (pathname.endsWith("/forgot")) action = "forgot";
  }

  if (!action) {
    return new Response(JSON.stringify({ error: "Missing action" }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }

  // =========================================================
  // SIGNUP
  // =========================================================
  if (action === "signup") {
    const name = (body.name || "").trim();
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";
    const phone = body.phone || null;
    const gender = body.gender || null;

    if (!name || !email || !password) {
      return new Response(JSON.stringify({ error: "Missing required fields: name, email, password" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      const existing = await DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      if (existing) {
        return new Response(JSON.stringify({ error: "User already exists" }), {
          status: 409,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      const hashed = await hashPassword(password);
      const recovery_code = makeRecoveryCode(12);

      await DB.prepare(
        "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(name, email, hashed, phone, gender, recovery_code).run();

      return new Response(JSON.stringify({
        message: "Signup successful",
        recovery_code
      }), {
        status: 201,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("Signup error:", err.stack || err);
      return new Response(JSON.stringify({ error: "Internal server error (signup)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // =========================================================
  // LOGIN
  // =========================================================
  if (action === "login") {
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";

    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      const hashed = await hashPassword(password);
      const stored = user.password || "";
      const isHashedMatch = (hashed === stored);
      const isPlainMatch = (password === stored);

      if (!isHashedMatch && !isPlainMatch) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      if (isPlainMatch && !isHashedMatch) {
        try {
          await DB.prepare("UPDATE users SET password = ? WHERE id = ?").bind(hashed, user.id).run();
        } catch (e) {
          console.error("Password upgrade failed:", e);
        }
      }

      const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone || null,
        gender: user.gender || null
      };

      return new Response(JSON.stringify({ message: "Login successful", user: safeUser }), {
        status: 200,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("Login error:", err.stack || err);
      return new Response(JSON.stringify({ error: "Internal server error (login)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // =========================================================
  // FORGOT PASSWORD / RESET
  // =========================================================
  if (action === "forgot") {
    const email = (body.email || "").trim().toLowerCase();

    if (!email) {
      return new Response(JSON.stringify({ error: "Missing email" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    try {
      const user = await DB.prepare("SELECT id, recovery_code FROM users WHERE email = ?").bind(email).first();
      if (!user) {
        return new Response(JSON.stringify({ message: "If an account exists, instructions were sent." }), {
          status: 200,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      if (body.recovery_code && body.new_password) {
        const provided = String(body.recovery_code);
        if (provided !== user.recovery_code) {
          return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
            status: 401,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
          });
        }

        const newHashed = await hashPassword(String(body.new_password));
        const newCode = makeRecoveryCode(12);
        await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE id = ?")
          .bind(newHashed, newCode, user.id)
          .run();

        return new Response(JSON.stringify({ message: "Password reset successful", recovery_code: newCode }), {
          status: 200,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }

      return new Response(JSON.stringify({ message: "If an account exists, follow the reset instructions you received." }), {
        status: 200,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    } catch (err) {
      console.error("Forgot error:", err.stack || err);
      return new Response(JSON.stringify({ error: "Internal server error (forgot)" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }
  }

  // =========================================================
  // UNKNOWN ACTION
  // =========================================================
  return new Response(JSON.stringify({ error: "Unknown action" }), {
    status: 400,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}
