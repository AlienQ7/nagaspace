// script.js -- full version

// ============ UTILS ============
function showAlert(msg) {
  alert(msg);
}

// Show the one-time recovery popup (copy / save)
function showRecoveryPopup(code, note = "Save this recovery code. You will only see it once.") {
  const overlay = document.createElement("div");
  overlay.id = "recovery-overlay";
  overlay.style = `
    position: fixed; inset: 0; display:flex; align-items:center; justify-content:center;
    background: rgba(0,0,0,0.6); z-index: 9999;
  `;
  overlay.innerHTML = `
    <div style="background:#fff; padding:22px; border-radius:10px; max-width:420px; width:90%; text-align:center;">
      <h2 style="margin:0 0 8px;color:var(--color-accent)">Important — Recovery Code</h2>
      <p style="margin:0 0 12px;">${note}</p>
      <div style="font-size:20px; font-weight:700; letter-spacing:2px; margin:6px 0; color:#111;">${code}</div>
      <div style="margin-top:14px;">
        <button id="copyRecoveryBtn">Copy</button>
        <button id="okRecoveryBtn" style="margin-left:10px;">I saved it</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("copyRecoveryBtn").onclick = async () => {
    try {
      await navigator.clipboard.writeText(code);
      alert("Copied to clipboard");
    } catch (e) {
      alert("Copy failed — manually copy it.");
    }
  };
  document.getElementById("okRecoveryBtn").onclick = () => {
    overlay.remove();
  };
}

// ============ ADS / PRODUCTS ============

async function loadAds(containerId = "adsList", userId = null) {
  try {
    const res = await fetch("/api/ads");
    if (!res.ok) throw new Error("Failed to fetch ads");
    const ads = await res.json();

    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = "";
    const filtered = userId ? ads.filter(ad => String(ad.user_id) === String(userId)) : ads;

    if (!filtered || filtered.length === 0) {
      container.innerHTML = "<p>No ads found.</p>";
      return;
    }

    filtered.forEach(ad => {
      const div = document.createElement("div");
      div.className = "ad-card";
      div.innerHTML = `
        <div class="ad-inner" onclick="viewAd(${ad.id})">
          <h3>${escapeHtml(ad.title)}</h3>
          <p>${escapeHtml(ad.description ? ad.description.substring(0, 120) + "..." : "No description")}</p>
          <p><strong>Location:</strong> ${escapeHtml(ad.location || "Unknown")}</p>
          <p><strong>Contact:</strong> ${escapeHtml(ad.contact || "N/A")}</p>
        </div>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error("Error loading ads:", err);
  }
}

function viewAd(id) {
  window.location.href = `productDetails.html?id=${id}`;
}

async function deleteAd(id) {
  if (!confirm("Are you sure you want to delete this ad?")) return;
  try {
    const res = await fetch("/api/ads", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    const data = await res.json();
    alert(data.message || "Deleted");
    location.reload();
  } catch (err) {
    console.error("Error deleting ad:", err);
  }
}

// ============ AUTH HANDLERS ============

async function handleSignup(e) {
  e && e.preventDefault();
  const name = (document.getElementById("signupName") || {}).value || (document.getElementById("username") || {}).value;
  const email = (document.getElementById("signupEmail") || {}).value || (document.getElementById("email") || {}).value;
  const password = (document.getElementById("signupPassword") || {}).value || (document.getElementById("password") || {}).value;
  const confirm = (document.getElementById("signupConfirmPassword") || {}).value || (document.getElementById("confirmPassword") || {}).value;

  if (!name || !email || !password) {
    return showAlert("Please fill name, email and password.");
  }
  if (String(name).trim().length < 5) return showAlert("Name must be at least 5 characters.");
  if (password.length < 8) return showAlert("Password must be at least 8 characters.");
  if (password !== confirm) return showAlert("Passwords do not match.");

  try {
    const res = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password }),
    });

    const json = await res.json();
    if (!res.ok) {
      return showAlert(json.error || "Signup failed");
    }

    // Show recovery code (only once)
    if (json.recovery_code) {
      showRecoveryPopup(json.recovery_code, "This recovery code is shown only once. Save it somewhere safe.");
    }

    showAlert("Account created successfully. You can now log in.");
    window.location.href = "index.html";
  } catch (err) {
    console.error("Signup error:", err);
    showAlert("Network error during signup.");
  }
}

async function handleLogin(e) {
  e && e.preventDefault();
  const email = (document.getElementById("loginEmail") || {}).value || (document.getElementById("emailLogin") || {}).value;
  const password = (document.getElementById("loginPassword") || {}).value || (document.getElementById("emailPassword") || {}).value;

  if (!email || !password) return showAlert("Please provide email and password");

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const json = await res.json();
    if (!res.ok) return showAlert(json.error || "Login failed");

    // Save user and redirect
    localStorage.setItem("user", JSON.stringify(json.user));
    window.location.href = "dashboard.html";
  } catch (err) {
    console.error("Login error:", err);
    showAlert("Network error during login.");
  }
}

async function handleReset(e) {
  e && e.preventDefault();
  const email = (document.getElementById("resetEmail") || {}).value;
  const recovery_code = (document.getElementById("resetCode") || {}).value;
  const new_password = (document.getElementById("resetNewPassword") || {}).value;
  const confirm = (document.getElementById("resetConfirmPassword") || {}).value;

  if (!email || !recovery_code || !new_password) return showAlert("Please provide email, recovery code and new password.");
  if (new_password.length < 8) return showAlert("New password must be at least 8 characters.");
  if (new_password !== confirm) return showAlert("Passwords do not match.");

  try {
    const res = await fetch("/api/auth/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, recovery_code, new_password }),
    });
    const json = await res.json();
    if (!res.ok) return showAlert(json.error || "Reset failed");

    if (json.recovery_code) {
      showRecoveryPopup(json.recovery_code, "Your password was reset successfully. This is your NEW recovery code (save it).");
    }

    showAlert("Password reset successful. Please login with your new password.");
    window.location.href = "index.html";
  } catch (err) {
    console.error("Reset error:", err);
    showAlert("Network error during reset.");
  }
}

// Basic HTML escape
function escapeHtml(s) {
  if (!s) return "";
  return String(s).replace(/[&<>"']/g, (m) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m]));
}

// ============ PAGE INIT ============
document.addEventListener("DOMContentLoaded", () => {
  // Wire up signup form(s)
  const signupForm = document.getElementById("signupForm");
  if (signupForm) signupForm.addEventListener("submit", handleSignup);

  // Wire up login form(s)
  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  // Wire up reset form
  const resetForm = document.getElementById("resetForm");
  if (resetForm) resetForm.addEventListener("submit", handleReset);

  // Auto-run ads/product loading depending on page
  const path = window.location.pathname;
  if (path.endsWith("profile.html")) {
    const user = JSON.parse(localStorage.getItem("user"));
    if (user && user.id) loadAds("myAds", user.id);
  } else if (path.endsWith("productDetails.html")) {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    if (id) {
      // small inline fetch for a single ad (if productDetails page expects it)
      fetch(`/api/ads?id=${encodeURIComponent(id)}`)
        .then(r => r.json())
        .then(ad => {
          if (ad && document.getElementById("productName")) {
            document.getElementById("productName").innerText = ad.title || "";
            const desc = ad.description || "";
            if (document.getElementById("description")) document.getElementById("description").innerText = desc;
            if (document.getElementById("description2")) document.getElementById("description2").innerText = desc;
            if (document.getElementById("price")) document.getElementById("price").innerText = ad.category || "";
            if (document.getElementById("location")) document.getElementById("location").innerHTML = `<i class="fa-solid fa-location-dot"></i> ${ad.location || ""}`;
            if (document.getElementById("phoneL")) document.getElementById("phoneL").innerText = ad.contact || "";
            if (document.getElementById("nameL")) document.getElementById("nameL").innerText = ad.user_id ? "User #" + ad.user_id : "Unknown";
          }
        })
        .catch(err => console.error(err));
    }
  } else {
    // try to load main ads on homepage if there's an element with id adsList
    if (document.getElementById("adsList")) loadAds("adsList");
  }
});
