// Content limits shared by the Claude step, the runner and the tests.
import { wordCount } from "./common.js";

export const SHORT_MAX_WORDS = 80;
export const FULL_MAX_WORDS = 500;

export function fullDescriptionWords(c) {
  const parts = [c.overview || "", ...(c.usage || []), ...(c.features || []), ...(c.specs || []).map((s) => `${s.name} ${s.value}`)];
  return parts.reduce((n, p) => n + wordCount(p), 0);
}

export function validateContent(c) {
  const problems = [];
  for (const k of ["name", "short_description", "overview"]) if (!String(c?.[k] || "").trim()) problems.push(`missing ${k}`);
  const s = wordCount(c?.short_description);
  if (s > SHORT_MAX_WORDS) problems.push(`short_description has ${s} words (max ${SHORT_MAX_WORDS})`);
  const f = fullDescriptionWords(c || {});
  if (f > FULL_MAX_WORDS) problems.push(`full description (overview+usage+features+specs) has ${f} words (max ${FULL_MAX_WORDS})`);
  const text = `${c?.short_description || ""} ${c?.overview || ""}`;
  if (text.trim() && !/[֐-׿]/.test(text)) problems.push("texts are not in Hebrew");
  return problems;
}
