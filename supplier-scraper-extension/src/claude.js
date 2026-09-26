// Claude calls. Bundled into lib/claude.bundle.js by `npm run build` (esbuild),
// so the extension loads without a build step for the user.
import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import { z } from "zod";
import { FULL_MAX_WORDS, SHORT_MAX_WORDS, validateContent } from "../lib/rules.js";

function client(settings) {
  return new Anthropic({
    apiKey: settings.apiKey,
    baseURL: settings.apiBaseUrl || undefined, // only used by the offline tests
    dangerouslyAllowBrowser: true,             // the key stays in this browser's extension storage
    maxRetries: 4,
  });
}

async function parse(settings, schema, content, extra = {}) {
  const resp = await client(settings).messages.parse({
    model: settings.model,
    max_tokens: 16000,
    messages: [{ role: "user", content }],
    output_config: { format: zodOutputFormat(schema) },
    ...extra,
  });
  if (resp.stop_reason === "refusal" || !resp.parsed_output) throw new Error(`Claude returned no answer (${resp.stop_reason})`);
  return resp.parsed_output;
}

// ---------- 1. How to find this product type on this site ----------

const Plan = z.object({
  keywords: z.array(z.string()).describe("words/phrases that identify this product type in product names, URLs and menus, in English, Hebrew and the site's language (e.g. 'thermal camera', 'thermal imager', 'infrared camera', 'thermography', 'מצלמה תרמית')"),
  links: z.array(z.number().int()).describe("indexes of links likely to lead to products of this type or to the product catalogue (category pages, product listings, shop, catalogue)"),
});

export async function planSearch(settings, productType, startUrl, links) {
  const list = links.map((l, i) => `${i}\t${l.title}\t${l.url}`).join("\n");
  return parse(settings, Plan,
    `I need to find every product of this type on the website ${startUrl}: "${productType}".\n` +
    `Below are the links on the start page (index, link text, URL). Give search keywords for this product type and pick the links worth following.\n\n${list}`);
}

// ---------- 2. Keep only products of the requested type ----------

const Selection = z.object({
  selected: z.array(z.number().int()).describe("indexes of the links that are individual product pages of the requested type"),
});

export async function selectProducts(settings, productType, candidates) {
  const chosen = [];
  for (let start = 0; start < candidates.length; start += 250) {
    const batch = candidates.slice(start, start + 250);
    const list = batch.map((c, i) => `${i}\t${c.title || ""}\t${c.type || ""}\t${c.url}`).join("\n");
    const out = await parse(settings, Selection,
      `These links were found on a website (index, link text, product category, URL).\n` +
      `Select the ones that are pages of individual products of this type: "${productType}".\n` +
      `Exclude accessories, spare parts, consumables, software, category/listing pages, articles, news and anything else.\n` +
      `If the same product appears under several URLs (languages, duplicates), select only one of them.\n\n${list}`);
    for (const i of out.selected) if (i >= 0 && i < batch.length) chosen.push(start + i);
  }
  return [...new Set(chosen)];
}

// ---------- 3. Who makes it, and where is the official site ----------

const Official = z.object({
  manufacturer: z.string().describe("brand / manufacturer name as the manufacturer writes it, e.g. 'FOTRIC'"),
  model: z.string().describe("product model name without the manufacturer, e.g. '348A'"),
  official_domains: z.array(z.string()).describe("domains of the manufacturer's own official websites (no distributors or marketplaces), e.g. ['fotric.com']"),
  official_product_url: z.string().describe("the product's page on the manufacturer's official site, or '' if none found"),
  official_downloads_url: z.string().describe("official page listing downloads (brochure/datasheet/manual) for the product, or ''"),
  site_is_manufacturer: z.boolean().describe("true if the website where the product was found is itself the manufacturer's official site"),
});

export async function identifyManufacturer(settings, { name, url, excerpt, known }) {
  const c = client(settings);
  const question =
    `A product page was found at ${url}\nProduct name on the page: ${name}\nPage excerpt:\n${excerpt.slice(0, 3000)}\n\n` +
    (known.length ? `Manufacturers already identified in this job: ${known.map((k) => `${k.manufacturer} = ${k.official_domains.join(", ")}`).join("; ")}\n\n` : "") +
    `Use web search to find:\n` +
    `1. The manufacturer (brand owner) of this product and its OFFICIAL website domains. Distributors, resellers, marketplaces and review sites are NOT official.\n` +
    `2. The product's page on the manufacturer's official website.\n` +
    `3. An official page with the product's brochure / datasheet / user manual downloads, if there is one.\n` +
    `4. Whether ${new URL(url).hostname} is itself the manufacturer's official site.\n` +
    `Only report URLs you actually saw in search results.`;
  const messages = [{ role: "user", content: question }];
  let resp;
  for (let i = 0; i < 5; i++) {
    resp = await c.messages.create({
      model: settings.model,
      max_tokens: 16000,
      tools: [{ type: "web_search_20260209", name: "web_search", max_uses: 6 }],
      messages,
    });
    if (resp.stop_reason !== "pause_turn") break;
    messages.push({ role: "assistant", content: resp.content });
  }
  if (resp.stop_reason === "refusal") throw new Error("Claude declined the manufacturer search");
  const answer = resp.content.filter((b) => b.type === "text").map((b) => b.text).join("\n");
  return parse(settings, Official, `Product found at ${url} (${name}).\nResearch notes:\n${answer}\n\nExtract the answer into the schema.`);
}

// ---------- 4. The Hebrew product entry ----------

const HebrewContent = z.object({
  name: z.string().describe("Hebrew product title in the house style, e.g. 'מצלמה תרמית 640X480 פיקסלים Fotric 348A'"),
  short_description: z.string().describe(`Hebrew, at most ${SHORT_MAX_WORDS} words`),
  overview: z.string().describe("Hebrew overview; paragraphs separated by a blank line"),
  usage: z.array(z.string()).describe("Hebrew bullet points: applications and how the product is used"),
  features: z.array(z.string()).describe("Hebrew bullet points: key features"),
  specs: z.array(z.object({ name: z.string(), value: z.string() })).describe("technical specifications; Hebrew labels, values as in the source"),
});

export function systemPrompt(glossary, styleExamples) {
  const examples = styleExamples.map((e, i) => `<example index="${i + 1}" url="${e.url}">\n${e.text}\n</example>`).join("\n");
  return `את/ה קופירייטר/ית טכני/ת בכיר/ה ב-NDT24, יבואנית ישראלית של ציוד לבדיקות לא הורסות (NDT), איתור נזילות מים, מצלמות צנרת, וידאוסקופים ומצלמות תרמיות.
המשימה: לכתוב דף מוצר בעברית לאתר, על סמך חומר מקור באנגלית (או בשפה אחרת) מאתר הספק, מאתר היצרן ומהברושור/קטלוג.

איך כותבים:
- עברית טבעית, עכשווית ומקצועית - כמו שטכנאי או איש מכירות בתחום בישראל מדבר וכותב היום. לא תרגום מילולי, לא לשון גבוהה או ארכאית, ולא מילים עבריות "מומצאות" שאף אחד בענף לא משתמש בהן.
- כשבענף בישראל משתמשים במונח הלועזי (למשל וידאוסקופ, פרוב, Wi-Fi, NETD, IP54) - משתמשים בו. שמות מותגים, דגמים, יחידות, תקנים ופרוטוקולים נשארים באותיות לטיניות.
- להשתמש במונחים מרשימת המונחים ומדוגמאות הסגנון של האתר. הדוגמאות הן המקור הקובע לסגנון, לטון ולאוצר המילים - לא לתוכן.
- כותרת המוצר (name) בפורמט של האתר: סוג המוצר בעברית + נתון מפתח אם רלוונטי + מותג + דגם. לדוגמה: "מצלמה תרמית 640X480 פיקסלים Fotric 348A", "Sniffer430 מכשיר לאיתור נזילות מים בגז".
- short_description: עד ${SHORT_MAX_WORDS} מילים - מה המוצר, למי הוא מיועד והיתרון המרכזי.
- התיאור המלא = overview + usage + features + specs, ביחד עד ${FULL_MAX_WORDS} מילים. usage מתאר גם איך משתמשים במוצר. כשאין מקום - לשמור את המפרטים החשובים ביותר.

עובדות:
- רק עובדות שמופיעות בחומר המקור. אסור להמציא נתונים, מספרים, תקנים, אחריות או טענות. מה שלא מופיע - לא נכתב.
- כשיש סתירה, עדיף המידע מאתר היצרן הרשמי ומהברושור שלו.
- בלי מחירים, בלי פרטי התקשרות, בלי סופרלטיבים שלא מופיעים במקור.

<glossary>
${glossary}
</glossary>

<style_examples>
${examples || "(no examples available)"}
</style_examples>`;
}

export function sourceMaterial(raw) {
  const parts = [`Manufacturer: ${raw.manufacturer}`, `Product name: ${raw.name}`];
  const descs = [...raw.descriptions].sort((a, b) => Number(b.official) - Number(a.official));
  for (const d of descs) parts.push(`\n=== ${d.official ? "OFFICIAL MANUFACTURER PAGE" : "SUPPLIER PAGE"}: ${d.source} ===\n${d.text}`);
  if (raw.specs.length) parts.push("\n=== SPEC TABLE ===\n" + raw.specs.map(([k, v]) => `${k}: ${v}`).join("\n"));
  return parts.join("\n").slice(0, 60000);
}

// pdfs: [{title, base64}] - official brochure / catalogue, read by Claude as extra source material.
export async function writeHebrew(settings, raw, { glossary, styleExamples, pdfs = [], attempts = 3 }) {
  const system = [{ type: "text", text: systemPrompt(glossary, styleExamples), cache_control: { type: "ephemeral" } }];
  const docs = pdfs.map((p) => ({ type: "document", title: p.title, source: { type: "base64", media_type: "application/pdf", data: p.base64 } }));
  const sources = sourceMaterial(raw);
  let feedback = "";
  let content = null;
  for (let i = 0; i < attempts; i++) {
    const resp = await client(settings).messages.parse({
      model: settings.model,
      max_tokens: 16000,
      system,
      messages: [{ role: "user", content: [...docs, { type: "text", text: `<sources>\n${sources}\n</sources>\n\nכתוב/י את דף המוצר.${feedback}` }] }],
      output_config: { format: zodOutputFormat(HebrewContent) },
    });
    if (resp.stop_reason === "refusal" || !resp.parsed_output) throw new Error(`Claude returned no content (${resp.stop_reason})`);
    content = resp.parsed_output;
    const problems = validateContent(content);
    if (!problems.length) return { content, problems };
    feedback = `\n\nבטיוטה הקודמת היו הבעיות הבאות - תקן/י:\n- ${problems.join("\n- ")}\nהטיוטה הקודמת:\n${JSON.stringify(content)}`;
  }
  return { content, problems: validateContent(content) };
}
