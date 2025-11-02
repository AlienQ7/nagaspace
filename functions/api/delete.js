export async function onRequestDelete({ request, env }) {
  try {
    const url = new URL(request.url);
    const id = url.searchParams.get("id");

    if (!id) {
      return new Response(JSON.stringify({ error: "Missing ad ID" }), {
        headers: { "Content-Type": "application/json" },
        status: 400,
      });
    }

    const result = await env.DB.prepare("DELETE FROM ads WHERE id = ?").bind(id).run();

    if (result.success || result.meta.changes > 0) {
      return new Response(JSON.stringify({ success: true, message: "Ad deleted" }), {
        headers: { "Content-Type": "application/json" },
      });
    } else {
      return new Response(JSON.stringify({ success: false, message: "Ad not found" }), {
        headers: { "Content-Type": "application/json" },
        status: 404,
      });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
}
