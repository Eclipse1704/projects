"""Stage 4: write the Hebrew product texts.

Two ways to fill content.he.json for a product:
  * automatically, with the Claude API (needs ANTHROPIC_API_KEY or `ant auth login`);
  * by Claude Code itself following SKILL.md (no API key needed) - it writes the same
    JSON and runs `run.py validate`.
"""
from __future__ import annotations

import json
import os

from pydantic import BaseModel, Field

from .common import word_count

SHORT_MAX_WORDS = 80
FULL_MAX_WORDS = 500
DEFAULT_MODEL = os.environ.get("CATALOG_MODEL", "claude-opus-5")


class Spec(BaseModel):
    name: str = Field(description="Spec label in Hebrew")
    value: str = Field(description="Value exactly as in the source; keep units/numbers in Latin characters")


class HebrewContent(BaseModel):
    product_name: str = Field(description="Hebrew display name: product type in Hebrew + manufacturer + model in Latin, e.g. 'מצלמה תרמית FOTRIC 226s'")
    category: str = Field(description="Product category in Hebrew")
    short_description: str = Field(description=f"Hebrew, at most {SHORT_MAX_WORDS} words")
    overview: str = Field(description="Hebrew overview paragraph(s)")
    usage: list[str] = Field(description="Hebrew bullet points: applications and how the product is used")
    features: list[str] = Field(description="Hebrew bullet points: key features")
    specs: list[Spec] = Field(description="Technical specifications")


SYSTEM = f"""You write Hebrew product catalogue entries for an Israeli distributor of professional equipment.
Rules:
- Use ONLY facts found in the supplied source material. Never invent specs, numbers, certifications or claims. If something is not in the sources, leave it out.
- Natural, professional Israeli Hebrew. Keep brand names, model numbers, units, standards and protocol names in Latin characters (e.g. FOTRIC 226s, IP54, 640×480, USB-C).
- short_description: at most {SHORT_MAX_WORDS} words - what it is, who it is for, the main benefit.
- The full description = overview + usage + features + specs; together at most {FULL_MAX_WORDS} words. Prefer the most important specs when space is tight.
- No marketing superlatives that are not in the source, no prices, no contact details."""


def full_description_words(c: dict) -> int:
    parts = [c.get("overview", "")] + c.get("usage", []) + c.get("features", [])
    parts += [f"{s['name']} {s['value']}" for s in c.get("specs", [])]
    return sum(word_count(p) for p in parts)


def validate_content(c: dict) -> list[str]:
    problems = []
    for key in ("product_name", "short_description", "overview"):
        if not (c.get(key) or "").strip():
            problems.append(f"missing {key}")
    if word_count(c.get("short_description", "")) > SHORT_MAX_WORDS:
        problems.append(f"short_description has {word_count(c['short_description'])} words (max {SHORT_MAX_WORDS})")
    n = full_description_words(c)
    if n > FULL_MAX_WORDS:
        problems.append(f"full description (overview+usage+features+specs) has {n} words (max {FULL_MAX_WORDS})")
    text = " ".join([c.get("short_description", ""), c.get("overview", "")])
    if text.strip() and not any("֐" <= ch <= "׿" for ch in text):
        problems.append("texts are not in Hebrew")
    return problems


def source_material(raw: dict, max_chars: int = 60_000) -> str:
    parts = [f"Manufacturer: {raw['manufacturer']}", f"Product name: {raw['name']}"]
    for d in sorted(raw["descriptions"], key=lambda d: not d.get("official")):
        tag = "OFFICIAL MANUFACTURER PAGE" if d.get("official") else "SUPPLIER PAGE"
        parts.append(f"\n=== {tag}: {d['source']} ===\n{d['text']}")
    if raw["specs"]:
        parts.append("\n=== SPEC TABLE ===\n" + "\n".join(f"{k}: {v}" for k, v in raw["specs"]))
    return "\n".join(parts)[:max_chars]


def generate(raw: dict, model: str = DEFAULT_MODEL, attempts: int = 3) -> dict:
    import anthropic

    client = anthropic.Anthropic()
    prompt = source_material(raw)
    feedback = ""
    content: dict = {}
    for _ in range(attempts):
        resp = client.messages.parse(
            model=model,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": f"<sources>\n{prompt}\n</sources>\n\nWrite the Hebrew catalogue entry.{feedback}"}],
            output_format=HebrewContent,
        )
        if resp.stop_reason == "refusal" or resp.parsed_output is None:
            raise RuntimeError(f"model returned no content (stop_reason={resp.stop_reason})")
        content = resp.parsed_output.model_dump()
        problems = validate_content(content)
        if not problems:
            return content
        feedback = "\n\nYour previous draft had these problems - fix them:\n- " + "\n- ".join(problems) + \
                   "\nPrevious draft:\n" + json.dumps(content, ensure_ascii=False)
    print(f"  ! content still has problems after {attempts} attempts: {validate_content(content)}")
    return content
