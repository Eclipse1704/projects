// Jacob's MC: Notion change-request watcher (Cloudflare Worker).
// Runs every minute (Cron Trigger "* * * * *"). When a post in the Notion calendar has text in
// "Requested changes" and nobody has typed in it for a minute, it marks the post "Queued" and fires
// the Claude task that applies the change (about 5-10 minutes later the post is updated in Notion).
// Costs nothing while there are no requests: Claude only runs when there is something to do.
//
// Secrets (Worker → Settings → Variables and Secrets):
//   NOTION_TOKEN   internal integration secret (the integration must be connected to the "All posts" database)
//   ROUTINE_URL    the task's API trigger URL from claude.ai/code/routines
//   ROUTINE_TOKEN  the task's API trigger token (sk-ant-oat01-...)

const DB = "2f733d99c04382a08c2981730460ddad"; // "All posts" database
const NOTION = "https://api.notion.com/v1";
const QUIET_MS = 120000; // Notion rounds edit times to the minute: wait until the text has been still for 1-2 minutes

const notion = (env, path, method, body) =>
  fetch(NOTION + path, {
    method,
    headers: { Authorization: `Bearer ${env.NOTION_TOKEN}`, "Notion-Version": "2022-06-28", "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

const setStatus = (env, id, name) =>
  notion(env, `/pages/${id}`, "PATCH", { properties: { "Review status": { select: name ? { name } : null } } });

async function run(env) {
  const r = await notion(env, `/databases/${DB}/query`, "POST", {
    filter: {
      and: [
        { property: "Requested changes", rich_text: { is_not_empty: true } },
        { property: "Review status", select: { does_not_equal: "Queued" } },
        { property: "Review status", select: { does_not_equal: "Updating" } },
      ],
    },
    page_size: 20,
  });
  if (!r.ok) return `Notion query failed ${r.status}: ${await r.text()}`;
  const rows = (await r.json()).results || [];
  const ready = rows.filter((p) => Date.now() - Date.parse(p.last_edited_time) >= QUIET_MS);
  if (!ready.length) return rows.length ? `${rows.length} request(s) still being typed` : "no change requests";

  const before = {};
  for (const p of ready) {
    before[p.id] = p.properties["Review status"]?.select?.name || null;
    await setStatus(env, p.id, "Queued");
  }
  const names = ready.map((p) => (p.properties["Post"]?.title || []).map((t) => t.plain_text).join("") || p.id);

  const f = await fetch(env.ROUTINE_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.ROUTINE_TOKEN}`,
      "anthropic-beta": "experimental-cc-routine-2026-04-01",
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text: `Started by the Notion watcher for: ${names.join(", ")}. Process the rows marked "Queued".` }),
  });
  if (!f.ok) {
    for (const p of ready) await setStatus(env, p.id, before[p.id]); // put them back so the next minute retries
    return `Could not start Claude (${f.status}): ${await f.text()}`;
  }
  return `Started Claude for: ${names.join(", ")}`;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(run(env).then((m) => console.log(m)));
  },
  // Opening the worker's URL runs one check and shows the result (handy for testing).
  async fetch(request, env) {
    return new Response(await run(env), { headers: { "Content-Type": "text/plain; charset=utf-8" } });
  },
};
