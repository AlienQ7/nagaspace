// /functions/api/ads.js
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  const url = new URL(request.url);
  const queryId = url.searchParams.get("id");

  // Helper to parse id from path like /api/ads/3
  function idFromPath() {
    try {
      const parts = url.pathname.split("/").filter(Boolean); // e.g. ["api","ads","3"]
      if (parts.length >= 3) {
        const last = parts[parts.length - 1];
        const n = Number(last);
        if (!Number.isNaN(n)) return n;
      }
    } catch (e) {}
    return null;
  }

  // ---------- GET ----------
  if (request.method === "GET") {
    try {
      const id = queryId || idFromPath();
      if (id) {
        const ad = await db.prepare("SELECT * FROM ads WHERE id = ?").bind(id).first();
        if (!ad) return new Response(JSON.stringify({ error: "Ad not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
        return new Response(JSON.stringify(ad), { headers: { "Content-Type": "application/json" } });
      }

      const { results } = await db.prepare("SELECT * FROM ads ORDER BY id DESC").all();
      return new Response(JSON.stringify(results), { headers: { "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err.message) }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // ---------- POST ----------
  if (request.method === "POST") {
    try {
      const data = await request.json();
      const title = data.title ?? null;
      const description = data.description ?? null;
      const category = data.category ?? null;
      const location = data.location ?? null;
      const contact = data.contact ?? null;

      if (!title || !contact) {
        return new Response(JSON.stringify({ error: "Missing required fields: title and contact" }), { status: 400, headers: { "Content-Type": "application/json" } });
      }

      // Insert only into columns that exist in your current table
      await db.prepare(
        "INSERT INTO ads (title, description, category, location, contact) VALUES (?, ?, ?, ?, ?)"
      ).bind(title, description, category, location, contact).run();

      return new Response(JSON.stringify({ success: true, message: "Ad added successfully!" }), { headers: { "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err.message) }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // ---------- DELETE ----------
  if (request.method === "DELETE") {
    try {
      // Accept id via JSON body, query param, or path
      let id = null;

      // Try JSON body
      try {
        const body = await request.json().catch(() => null);
        if (body && body.id) id = body.id;
      } catch (e) {}

      // Try query param
      if (!id && queryId) id = queryId;

      // Try path
      if (!id) {
        const p = idFromPath();
        if (p) id = p;
      }

      if (!id) {
        return new Response(JSON.stringify({ error: "Missing ad id for deletion" }), { status: 400, headers: { "Content-Type": "application/json" } });
      }

      const result = await db.prepare("DELETE FROM ads WHERE id = ?").bind(id).run();

      // D1 returns meta.changes sometimes; be permissive
      const deleted = (result && result.meta && result.meta.changes && result.meta.changes > 0) || (result && result.success);
      if (deleted) {
        return new Response(JSON.stringify({ success: true, message: "Ad deleted successfully" }), { headers: { "Content-Type": "application/json" } });
      } else {
        return new Response(JSON.stringify({ success: false, message: "Ad not found or not deleted" }), { status: 404, headers: { "Content-Type": "application/json" } });
      }
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err.message) }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // Method not allowed
  return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { "Content-Type": "application/json" } });
}
