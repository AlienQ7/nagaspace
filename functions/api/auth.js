// functions/api/auth.js
export async function onRequest(context) {
  const { request, env } = context;
  const DB = env.DB;

  const CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // --- Helpers ---
  async function hashPassword(str) {
    const enc = new TextEncoder();
    const data = enc.encode(String(str));
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function makeRecoveryCode(len = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    let out = "";
    for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
    return out;
  }

  // --- Parse request ---
  let body = {};
  try {
    if (["POST", "PUT"].includes(request.method)) {
      body = await request.json().catch(() => ({}));
    }
  } catch {
    body = {};
  }

  const url = new URL(request.url);
  let action = (body.action || url.searchParams.get("action") || "").toString().toLowerCase();
  const pathname = url.pathname || "";
  if (!action) {
    if (pathname.endsWith("/signup")) action = "signup";
    else if (pathname.endsWith("/login")) action = "login";
    else if (pathname.endsWith("/forgot") || pathname.endsWith("/recover")) action = "forgot";
  }

  if (!action) {
    return new Response(
      JSON.stringify({ error: "Missing action. Use ?action=signup|login|forgot or body.action." }),
      { status: 400, headers: CORS_HEADERS }
    );
  }

  // ---------------------------
  // SIGNUP
  // ---------------------------
  if (action === "signup") {
    const name = (body.name || "").trim();
    const email = (body.email || "").trim().toLowerCase();
    const password = body.password || "";
    const phone = body.phone || null;
    const gender = body.gender || null;

    if (!name || !email || !password) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: name, email, password" }),
        { status: 400, headers: CORS_HEADERS }
      );
    }

    try {
      const existing = await DB.prepare("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .first();
      if (existing) {
        return new Response(JSON.stringify({ error: "User already exists" }), {
          status: 409,
          headers: CORS_HEADERS,
        });
      }

      const hashedPassword = await hashPassword(password);
      const recoveryCode = makeRecoveryCode(12);
      const recoveryHashed = await hashPassword(recoveryCode);

      await DB.prepare(
        "INSERT INTO users (name, email, password, phone, gender, recovery_code) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(name, email, hashedPassword, phone, gender, recoveryHashed).run();

      return new Response(
        JSON.stringify({ message: "Signup successful", recovery_code: recoveryCode }),
        { status: 201, headers: CORS_HEADERS }
      );
    } catch (err) {
      console.error("Signup error:", err);
      return new Response(JSON.stringify({ error: "Internal server error (signup)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // ---------------------------
  // LOGIN
  // ---------------------------
  if (action === "login") {
    const email = (body.email || "").trim().toLowerCase();
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
      const isPlainMatch = password === stored; // legacy

      if (!isHashedMatch && !isPlainMatch) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers: CORS_HEADERS,
        });
      }

      // Upgrade plaintext to hashed if needed
      if (isPlainMatch && !isHashedMatch) {
        try {
          await DB.prepare("UPDATE users SET password = ? WHERE id = ?")
            .bind(hashed, user.id)
            .run();
        } catch (e) {
          console.error("Password upgrade failed:", e);
        }
      }

      const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone ?? null,
        gender: user.gender ?? null,
      };

      return new Response(
        JSON.stringify({ message: "Login successful", user: safeUser }),
        { status: 200, headers: CORS_HEADERS }
      );
    } catch (err) {
      console.error("Login error:", err);
      return new Response(JSON.stringify({ error: "Internal server error (login)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // ---------------------------
  // FORGOT / RECOVER
  // ---------------------------
  if (action === "forgot") {
    const email = (body.email || "").trim().toLowerCase();
    if (!email) {
      return new Response(JSON.stringify({ error: "Missing email" }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    try {
      const user = await DB.prepare(
        "SELECT id, recovery_code FROM users WHERE email = ?"
      ).bind(email).first();

      if (!user) {
        return new Response(
          JSON.stringify({ message: "If an account exists, instructions were sent." }),
          { status: 200, headers: CORS_HEADERS }
        );
      }

      if (body.recovery_code && body.new_password) {
        const provided = String(body.recovery_code);
        const providedHash = await hashPassword(provided);

        if (!user.recovery_code || providedHash !== user.recovery_code) {
          return new Response(JSON.stringify({ error: "Invalid recovery code" }), {
            status: 401,
            headers: CORS_HEADERS,
          });
        }

        const newHashed = await hashPassword(String(body.new_password));
        const newCode = makeRecoveryCode(12);
        const newCodeHashed = await hashPassword(newCode);

        await DB.prepare(
          "UPDATE users SET password = ?, recovery_code = ? WHERE id = ?"
        ).bind(newHashed, newCodeHashed, user.id).run();

        return new Response(
          JSON.stringify({ message: "Password reset successful", recovery_code: newCode }),
          { status: 200, headers: CORS_HEADERS }
        );
      }

      return new Response(
        JSON.stringify({
          message: "If an account exists, follow the reset instructions you received.",
        }),
        { status: 200, headers: CORS_HEADERS }
      );
    } catch (err) {
      console.error("Forgot error:", err);
      return new Response(JSON.stringify({ error: "Internal server error (forgot)" }), {
        status: 500,
        headers: CORS_HEADERS,
      });
    }
  }

  // ---------------------------
  // DELETE ACCOUNT
  // ---------------------------
  if (action === "delete") {
    const email = (body.email || "").trim().toLowerCase();
    if (!email) {
      return new Response(JSON.stringify({ error: "Missing email" }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    try {
      const result = await DB.prepare("DELETE FROM users WHERE email = ?")
        .bind(email)
        .run();
      if (result.meta.changes > 0) {
        return new Response(
          JSON.stringify({ success: true, message: "Account deleted" }),
          { status: 200, headers: CORS_HEADERS }
        );
      } else {
        return new Response(
          JSON.stringify({ success: false, error: "User not found" }),
          { status: 404, headers: CORS_HEADERS }
        );
      }
    } catch (err) {
      console.error("Delete account error:", err);
      return new Response(
        JSON.stringify({ success: false, error: "Internal server error (delete)" }),
        { status: 500, headers: CORS_HEADERS }
      );
    }
  }

  return new Response(JSON.stringify({ error: "Unknown action" }), {
    status: 400,
    headers: CORS_HEADERS,
  });
}
