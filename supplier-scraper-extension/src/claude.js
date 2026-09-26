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
  });
}

// ---------- Step 1: keep only the requested product type ----------

const Selection = z.object({
  selected: z.array(z.number().int()).describe("indexes of the items that are products of the requested type"),
});

export async function selectProducts(settings, productType, candidates) {
  if (!productType.trim()) return candidates.map((_, i) => i);
  const list = candidates.map((c, i) => `${i}\t${c.title || ""}\t${c.type || ""}\t${c.url}`).join("\n");
  const resp = await client(settings).messages.parse({
    model: settings.model,
    max_tokens: 16000,
    messages: [{
      role: "user",
      content: `These links were found on a supplier website (index, link text, product type, URL).\n` +
        `Select the ones that are individual product pages of this type: "${productType}".\n` +
        `Exclude accessories, spare parts, software, category pages, articles and anything else.\n\n${list}`,
    }],
    output_config: { format: zodOutputFormat(Selection) },
  });
  if (resp.stop_reason === "refusal" || !resp.parsed_output) throw new Error(`Claude returned no selection (${resp.stop_reason})`);
  return [...new Set(resp.parsed_output.selected)].filter((i) => i >= 0 && i < candidates.length);
}

// ---------- Step 2: write the Hebrew product entry ----------

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
המשימה: לכתוב דף מוצר בעברית לאתר, על סמך חומר מקור באנגלית (או בשפה אחרת) מאתר הספק והיצרן.

איך כותבים:
- עברית טבעית, עכשווית ומקצועית - כמו שטכנאי או איש מכירות בתחום בישראל מדבר וכותב היום. לא תרגום מילולי, לא לשון גבוהה או ארכאית, ולא מילים עבריות "מומצאות" שאף אחד בענף לא משתמש בהן.
- כשבענף בישראל משתמשים במונח הלועזי (למשל וידאוסקופ, פרוב, Wi-Fi, NETD, IP54) - משתמשים בו. שמות מותגים, דגמים, יחידות, תקנים ופרוטוקולים נשארים באותיות לטיניות.
- להשתמש במונחים מרשימת המונחים ומדוגמאות הסגנון של האתר. הדוגמאות הן המקור הקובע לסגנון, לטון ולאוצר המילים - לא לתוכן.
- כותרת המוצר (name) בפורמט של האתר: סוג המוצר בעברית + נתון מפתח אם רלוונטי + מותג + דגם. לדוגמה: "מצלמה תרמית 640X480 פיקסלים Fotric 348A", "Sniffer430 מכשיר לאיתור נזילות מים בגז".
- short_description: עד ${SHORT_MAX_WORDS} מילים - מה המוצר, למי הוא מיועד והיתרון המרכזי.
- התיאור המלא = overview + usage + features + specs, ביחד עד ${FULL_MAX_WORDS} מילים. כשאין מקום - לשמור את המפרטים החשובים ביותר.

עובדות:
- רק עובדות שמופיעות בחומר המקור. אסור להמציא נתונים, מספרים, תקנים, אחריות או טענות. מה שלא מופיע - לא נכתב.
- כשיש סתירה, עדיף המידע מאתר היצרן הרשמי.
- בלי מחירים, בלי פרטי התקשרות, בלי סופרלטיבים שלא מופיעים במקור.

<glossary>
${glossary}
</glossary>

<style_examples>
${examples || "(no examples available)"}
</style_examples>`;
}

export function sourceMaterial(raw, category) {
  const parts = [`Manufacturer: ${raw.manufacturer}`, `Product name: ${raw.name}`];
  if (category) parts.push(`Shop category: ${category}`);
  const descs = [...raw.descriptions].sort((a, b) => Number(b.official) - Number(a.official));
  for (const d of descs) parts.push(`\n=== ${d.official ? "OFFICIAL MANUFACTURER PAGE" : "SUPPLIER PAGE"}: ${d.source} ===\n${d.text}`);
  if (raw.specs.length) parts.push("\n=== SPEC TABLE ===\n" + raw.specs.map(([k, v]) => `${k}: ${v}`).join("\n"));
  return parts.join("\n").slice(0, 60000);
}

export async function writeHebrew(settings, raw, { glossary, styleExamples, category, attempts = 3 }) {
  const system = [{ type: "text", text: systemPrompt(glossary, styleExamples), cache_control: { type: "ephemeral" } }];
  const sources = sourceMaterial(raw, category);
  let feedback = "";
  let content = null;
  for (let i = 0; i < attempts; i++) {
    const resp = await client(settings).messages.parse({
      model: settings.model,
      max_tokens: 16000,
      system,
      messages: [{ role: "user", content: `<sources>\n${sources}\n</sources>\n\nכתוב/י את דף המוצר.${feedback}` }],
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
