export async function onRequestGet({ env }) {
  try {
    const { results } = await env.IOT_DB.prepare(
      `SELECT id, title, description, price, category, image, created_at
       FROM listings
       ORDER BY created_at DESC`
    ).all();

    return new Response(JSON.stringify(results), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
