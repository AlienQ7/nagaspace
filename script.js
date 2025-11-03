// script.js
// Centralized auth + ads helper (auth-focused part shown)

document.addEventListener("DOMContentLoaded", () => {
  const signupForm = document.getElementById("signupForm");
  const loginForm = document.getElementById("loginForm");
  const forgotForm = document.getElementById("forgotForm");

  // Helper: generic fetch wrapper
  async function postAuth(payload) {
    try {
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      console.error("Network/fetch error:", err);
      return { ok: false, status: 0, data: { error: "Network error" } };
    }
  }

  // -----------------------
  // SIGNUP
  // -----------------------
  if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const name = (document.getElementById("signupName")?.value || "").trim();
      const email = (document.getElementById("signupEmail")?.value || "").trim().toLowerCase();
      const password = (document.getElementById("signupPassword")?.value || "");
      const confirm = (document.getElementById("signupConfirmPassword")?.value || "");

      if (!name || !email || !password) {
        alert("Please fill name, email and password.");
        return;
      }
      if (password.length < 8) {
        alert("Password must be at least 8 characters.");
        return;
      }
      if (password !== confirm) {
        alert("Passwords do not match.");
        return;
      }

      // call signup
      const { ok, status, data } = await postAuth({ action: "signup", name, email, password });

      console.log("signup result", { ok, status, data });

      if (!ok) {
        alert(data.error || "Signup failed");
        return;
      }

      // success: show recovery code (API returns recovery_code)
      if (data.recovery_code) {
        showRecoveryModal(data.recovery_code, () => {
          // redirect to login after user confirms
          window.location.href = "index.html";
        });
      } else {
        alert(data.message || "Signup successful. Please login.");
        window.location.href = "index.html";
      }
    });
  }

  // -----------------------
  // LOGIN
  // -----------------------
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = (document.getElementById("loginEmail")?.value || "").trim().toLowerCase();
      const password = (document.getElementById("loginPassword")?.value || "");

      if (!email || !password) {
        alert("Please fill both email and password.");
        return;
      }

      const { ok, status, data } = await postAuth({ action: "login", email, password });

      console.log("login result", { ok, status, data });

      if (!ok) {
        alert(data.error || "Login failed");
        return;
      }

      if (data.user) {
        localStorage.setItem("user", JSON.stringify(data.user));
        alert("Login successful");
        window.location.href = "dashboard.html";
      } else {
        alert(data.message || "Login successful (no user object returned)");
        window.location.href = "dashboard.html";
      }
    });
  }

  // -----------------------
  // FORGOT / RECOVER
  // -----------------------
  if (forgotForm) {
    forgotForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = (document.getElementById("forgotEmail")?.value || "").trim().toLowerCase();
      const recoveryCode = (document.getElementById("forgotRecoveryCode")?.value || "").trim();
      const newPassword = (document.getElementById("forgotNewPassword")?.value || "");

      if (!email) {
        alert("Please enter your email.");
        return;
      }

      // If user provided recoveryCode + newPassword -> attempt reset
      if (recoveryCode && newPassword) {
        if (newPassword.length < 8) {
          alert("New password must be at least 8 characters.");
          return;
        }

        const { ok, status, data } = await postAuth({
          action: "forgot",
          email,
          recovery_code: recoveryCode,
          new_password: newPassword,
        });

        console.log("recover attempt", { ok, status, data });

        if (!ok) {
          alert(data.error || "Password reset failed");
          return;
        }

        // API returns new recovery_code when successful
        if (data.recovery_code) {
          showRecoveryModal(data.recovery_code, () => {
            window.location.href = "index.html";
          }, "Password reset successful — here's your NEW recovery code (save it).");
        } else {
          alert(data.message || "Password reset successful");
          window.location.href = "index.html";
        }
        return;
      }

      // Otherwise start reset flow (email only) -> server responds with generic message
      const { ok, status, data } = await postAuth({ action: "forgot", email });

      console.log("forgot start", { ok, status, data });

      if (!ok && data.error) {
        alert(data.error || "Failed to start reset flow");
        return;
      }

      alert(data.message || "If an account exists, instructions were sent.");
      // keep user on same page to enter recovery code and new password if they got it
    });
  }

  // -----------------------
  // UI: modal to show recovery code (copy + confirm)
  // -----------------------
  function showRecoveryModal(code, onOk, title = "IMPORTANT: Your recovery code") {
    // create overlay elements
    const overlay = document.createElement("div");
    overlay.style = `
      position:fixed;left:0;top:0;width:100%;height:100%;
      display:flex;align-items:center;justify-content:center;
      background:rgba(0,0,0,0.6);z-index:99999;
    `;

    const card = document.createElement("div");
    card.style = `
      background:#fff;padding:20px;border-radius:10px;max-width:420px;width:90%;
      font-family:system-ui,Segoe UI,Roboto,Arial;
    `;

    card.innerHTML = `
      <h3 style="margin:0 0 8px;color: #ffb300;">${title}</h3>
      <p style="margin:0 0 8px;">This code is shown only once. Save it securely.</p>
      <div id="recoCode" style="font-weight:700;font-size:18px;margin:8px 0;padding:10px;border-radius:6px;border:1px solid #ddd;background:#f9f9f9;">${code}</div>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button id="copyRecoveryBtn">Copy</button>
        <button id="okRecoveryBtn">I saved it</button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    document.getElementById("copyRecoveryBtn").onclick = async () => {
      try {
        await navigator.clipboard.writeText(code);
        alert("Recovery code copied");
      } catch (err) {
        // fallback
        const textarea = document.createElement("textarea");
        textarea.value = code;
        document.body.appendChild(textarea);
        textarea.select();
        try { document.execCommand("copy"); alert("Recovery code copied"); } catch (e) { alert("Copy failed — manually copy"); }
        textarea.remove();
      }
    };

    document.getElementById("okRecoveryBtn").onclick = () => {
      overlay.remove();
      if (typeof onOk === "function") onOk();
    };
  }
});
