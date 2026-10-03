---
name: genjutsu
description: Run Higgsfield Genjutsu video-to-video generation through the pay-per-second Higgsfield API (not subscription credits). Three modes - motion transfer (recast a video - new character, outfit, location or style from reference images while keeping the original motion, camera and timing), object swap (replace specific elements, keep the rest of the shot) and restyle (turn a video into a preset visual style such as anime or claymation, keeping motion and audio). Use whenever the user asks for Genjutsu, Higgsfield motion transfer, object swap, restyle, recasting / re-skinning / character-swapping a video, putting someone or something from a reference image into an existing clip, or converting a video into an art style. Every submission costs real money, so it always shows duration, resolution and estimated cost and waits for the user's confirmation.
---

# Genjutsu (Higgsfield API, pay per second)

Script: `${CLAUDE_SKILL_DIR}/genjutsu.py` (the directory that contains this SKILL.md).
Prices and defaults: `${CLAUDE_SKILL_DIR}/config.json`. Standard-library Python 3, no installs needed; uses
`ffprobe` when present and otherwise reads the MP4 header itself.

## Hard rules (money is involved)

1. **Never submit without explicit confirmation.** Always run `run` first. It uploads, estimates and
   saves a plan but never charges. Show the user the cost check block, then ask. Only a clear "yes" to
   *that* plan (that duration, resolution and price) counts. Changing anything means a new `run`.
2. **One submit per plan.** `submit <plan>` is the only paid step. Never run it twice, never create a
   new plan to "retry" a slow, stuck or failed job unless the user asks for a new paid job.
3. **If polling stops** (timeout, tool timeout, Ctrl+C, network trouble): use `resume <plan>`. It only
   polls the existing `request_id`, never creates a request.
4. **If submit exits with code 2** (outcome unknown): tell the user. Do not re-send on your own. Only
   if they agree, run `submit <plan> --replay-same-key`. It reuses the plan's Idempotency-Key, so per the
   Higgsfield docs an already accepted job is returned rather than duplicated.
5. **Credentials** come from `HF_API_KEY_ID` and `HF_API_KEY_SECRET`. Never echo, print, log or write
   them anywhere. Check presence only:
   `test -n "$HF_API_KEY_ID" && test -n "$HF_API_KEY_SECRET" && echo set || echo missing`

## Workflow

1. **Collect inputs**
   - Source video: local `.mp4`/`.m4v` or a public URL. Min 4 s. Longer than 30 s is trimmed to the first
     30 s (billed as 30 s). A local `.mov` must be converted to MP4 first; the script prints the ffmpeg command.
   - Reference images, in order: local jpg/png/webp/gif or public URLs. 1-8 for motion transfer and
     object swap; optional 0-5 character images for restyle.
   - Optional prompt (max 10,000 chars). Use `--prompt-file` for long or quote-heavy prompts.
   - Mode:
     - `motion-transfer` (default): recast the whole shot from the reference images.
     - `object-swap`: swap specific elements, keep everything else. Needs at least 409,600 px per
       frame (e.g. 854x480 or larger).
     - `restyle`: apply one style preset (`--preset`, required). Keeps motion, composition and source
       audio. Without images it restyles the people already in the video; with images (max 5) it uses
       them as character references. Source max 200 MiB, each image max 64 MiB. Output duration/FPS
       can differ slightly from the source.
   - Resolution: default **1080p** (highest) unless the user says otherwise. Options 1080p / 720p / 480p.

   For restyle, list the styles first (free) and let the user pick one by name:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/genjutsu.py" presets [search-text]
   ```
   `--preset` accepts the UUID or a name. A name must match exactly one style (exact match first,
   then substring); the summary shows the resolved name and UUID so the user confirms the right style.

2. **Plan + cost check (free)**, run from the user's project directory so results land in `./outputs`:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/genjutsu.py" run --video clip.mp4 --image ref1.png ref2.jpg \
     --prompt "optional instructions" [--mode object-swap] [--resolution 720p] [--max-cost 25]

   python3 "${CLAUDE_SKILL_DIR}/genjutsu.py" run --mode restyle --video clip.mp4 \
     --preset "Cel-Shaded CG Anime" [--image character.png] [--prompt "keep her pink hair"]
   ```
   Use `--dry-run` to get an estimate without credentials, uploads or any API call.
   Relay the `=== Genjutsu ... cost check ===` block to the user (duration, billed seconds,
   resolution, ESTIMATE, server quote, other tiers), plus the plan path. Then ask for confirmation.

3. **Submit (paid) only after the user says yes**:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/genjutsu.py" submit outputs/jobs/<plan>.json
   ```
   Generation can take many minutes. Run it with the Bash tool in the background (or with the maximum
   timeout) and wait for it to finish. Do not start a second submit while waiting.

4. **Report** the printed `video saved to:` path and `video URL:` (Higgsfield keeps outputs at least
   7 days; the script always downloads to `./outputs`).

Other commands (never create a paid request):
- `resume <plan|request_id>`: keep polling and download.
- `status <plan|request_id>`: one status check.
- `cancel <plan|request_id>`: cancel while still `queued` (refunded). Not possible once `in_progress`.
- `presets [search]`: list restyle styles (id, name, preview image).

Exit codes: 0 ok, 1 error / failed job, 2 submit outcome unknown, 3 polling stopped (job still
running, use `resume`), 130 interrupted.

## Pricing

List prices (`config.json`, USD per source second, before discounts, same for all three modes;
the restyle docs call them approximate):
480p $0.318, 720p $0.681, 1080p $1.632. Duration is trimmed to 30 s, then rounded **up** to whole
seconds. The script also asks Higgsfield's free estimate endpoint for an account-specific quote and
uses the higher of the two for `--max-cost` / `max_cost_usd` checks. If a price is missing, the
script refuses to plan. Ask the user for the current price and write it into `config.json`.
Failed, nsfw and canceled requests are not charged.

## API facts (from docs.higgsfield.ai, checked 2026-10-03)

- Motion transfer: `POST https://api.higgsfield.ai/higgsfield/genjutsu/motion-transfer/v1.0`
- Object swap: `POST https://api.higgsfield.ai/higgsfield/genjutsu/object-swap/v1.0`
- Restyle: `POST https://api.higgsfield.ai/higgsfield/genjutsu/restyle/v1.0`
- Body (motion transfer, object swap): `video_url` (required), `image_urls` (required, 1-8),
  `prompt` (default ""), `resolution` (`480p` | `720p` | `1080p`, API default 720p).
- Body (restyle): `video_url` (required), `preset_id` (required UUID), `image_urls` (optional, 0-5,
  default []), `prompt`, `resolution`. `null` is not accepted.
- No other fields on any mode (`additionalProperties: false`).
- Restyle styles: `GET https://api.higgsfield.ai/models/higgsfield/genjutsu/restyle/v1.0/presets`
  returns `{"items": [{"id", "name", "preview_url"}]}`; send `items[].id` as `preset_id`.
- Auth: `Authorization: Key $HF_API_KEY_ID:$HF_API_KEY_SECRET`. Idempotency via `Idempotency-Key` header.
- Uploads: `POST /files/generate-upload-url {"content_type"}` returns `upload_url` + `upload_headers` + `public_url`;
  PUT the file with exactly those headers (no credentials); video must be `video/mp4`.
- Lifecycle: `queued`, `in_progress`, then `completed` / `failed` / `nsfw` / `canceled`; output at `video.url`.
- Optional completion webhook: `?hf_webhook=<https url>` on submit (`--webhook`).
