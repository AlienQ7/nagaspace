// functions/api/auth.js

export async function onRequest(context) {
  const { request, env } = context;
  const DB = env.DB; // D1 binding

  const CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };

  // Handle preflight
  if (request.method === "OPTIONS") {
    return new Response(JSON.stringify({ ok: true }), { status: 204, headers: CORS_HEADERS });
  }

  // --- Helpers ---
  async function hashPassword(password) {
    const enc = new TextEncoder();
    const data = enc.encode(String(password));
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function makeRecoveryCode(len = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    const rand = crypto.getRandomValues;
    while (out.length < len) {
      const r = new Uint32Array(1);
      rand(r);
      let v = r[0];
      // extract characters from the 32-bit integer
      while (v && out.length < len) {
        out += chars[v % chars.length];
        v = Math.floor(v / chars.length);
      }
    }
    return out;
  }

  // --- Parse action and JSON body safely ---
  let body = {};
  try {
    // attempt parse only for methods likely to have body
    if (request.method === "POST" || request.method === "PUT") {
      body = await request.json().catch(() => ({}));
    }
  } catch (e) {
    // ignore; we'll validate later
    body = {};
  }

  const url = new URL(request.url);
  // priority: body.action -> query param action -> path fragments (/signup etc)
  let action = (body.action || url.searchParams.get("action") || "").toString().toLowerCase();
  const pathname = url.pathname || "";
  if (!action) {
    if (pathname.endsWith("/signup")) action = "signup";
    else if (pathname.endsWith("/login")) action = "login";
    else if (pathname.endsWith("/forgot") || pathname.endsWith("/reset") || pathname.endsWith("/recover"))
      action = "forgot";
  }

  if (!action) {
    return new Response(JSON.stringify({ error: "Missing action. Use ?action=signup|login|forgot or { action } in body." }), {
      status: 400,
      headers: CORS_HEADERS,
    });
  }

  // =========================================================
  // SIGNUP
  // =========================================================
  if (action === "signup") {
    const name = (body.name || "").toString().trim();
    const email = (body.email || "").toString().trim().toLowerCase();
    const password = body.password || "";
    const phone = body.phone || null;
    const gender = body.gender || null;

    if (!name || !email || !password) {
      return new Response(JSON.stringify({ error: "Missing required fields: name, email, password" }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    try {
      // check existing user
      const existing = await DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      if (existing) {
        return new Response(JSON.stringify({ error: "User already exists" }), {
          status: 409,
          headers: CORS_HEADERS,
        });
      }

      const hashed = await hashPassword(password);
      const recovery_code = makeRecoveryCode(12);

      // insert user (D1 accepts nulls)
      await DB.prepare(
        "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
      )
        .bind(name, email, hashed, phone, gender, recovery_code)
        .run();

      // return recovery_code once (client must show/save it)
      return new Response(JSON.stringify({ message: "Signup successful", recovery_code }), {
        status: 201,
        headers: CORS_HEADERS,
      });
    } catch (err) {
      console.error("Signup error:", err && (err.stack || err));
      return new Response(JSON.stringify({ error: "Internal server error (signup)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // =========================================================
  // LOGIN
  // =========================================================
  if (action === "login") {
    const email = (body.email || "").toString().trim().toLowerCase();
    const password = body.password || "";

    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Missing email or password" }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    try {
      const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: CORS_HEADERS,
        });
      }

      const hashed = await hashPassword(password);
      const stored = user.password || "";
      const isHashedMatch = hashed === stored;
      const isPlainMatch = password === stored; // for legacy plaintext stored passwords

      if (!isHashedMatch && !isPlainMatch) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: CORS_HEADERS,
        });
      }

      // Upgrade plaintext password to hashed form if needed (non-fatal if update fails)
      if (isPlainMatch && !isHashedMatch) {
        try {
          await DB.prepare("UPDATE users SET password = ? WHERE id = ?").bind(hashed, user.id).run();
        } catch (e) {
          console.error("Password upgrade failed:", e && (e.stack || e));
        }
      }

      const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone ?? null,
        gender: user.gender ?? null,
      };

      return new Response(JSON.stringify({ message: "Login successful", user: safeUser }), {
        status: 200,
        headers: CORS_HEADERS,
      });
    } catch (err) {
      console.error("Login error:", err && (err.stack || err));
      return new Response(JSON.stringify({ error: "Internal server error (login)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // =========================================================
  // FORGOT / RECOVERY
  // =========================================================
  if (action === "forgot") {
    const email = (body.email || "").toString().trim().toLowerCase();
    if (!email) {
      return new Response(JSON.stringify({ error: "Missing email" }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    try {
      const user = await DB.prepare("SELECT id, recovery_code FROM users WHERE email = ?").bind(email).first();

      if (!user) {
        // do not signal account absence
        return new Response(JSON.stringify({ message: "If an account exists, instructions were sent." }), {
          status: 200,
          headers: CORS_HEADERS,
        });
      }

      // If client provided recovery_code + new_password -> perform reset
      if (body.recovery_code && body.new_password) {
        const provided = String(body.recovery_code);
        if (!user.recovery_code || provided !== user.recovery_code) {
          return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
            status: 401,
            headers: CORS_HEADERS,
          });
        }

        const newHashed = await hashPassword(String(body.new_password));
        const newCode = makeRecoveryCode(12);
        await DB.prepare("UPDATE users SET password = ?, recovery_code = ? WHERE id = ?")
          .bind(newHashed, newCode, user.id)
          .run();

        return new Response(JSON.stringify({ message: "Password reset successful", recovery_code: newCode }), {
          status: 200,
          headers: CORS_HEADERS,
        });
      }

      // Otherwise: client initiated reset (no email flow implemented here)
      return new Response(JSON.stringify({ message: "If an account exists, follow the reset instructions you received." }), {
        status: 200,
        headers: CORS_HEADERS,
      });
    } catch (err) {
      console.error("Forgot error:", err && (err.stack || err));
      return new Response(JSON.stringify({ error: "Internal server error (forgot)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // Unknown action
  return new Response(JSON.stringify({ error: "Unknown action" }), {
    status: 400,
    headers: CORS_HEADERS,
  });
}
