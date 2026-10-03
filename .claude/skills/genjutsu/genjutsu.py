#!/usr/bin/env python3
"""Run Higgsfield Genjutsu (motion transfer / object swap) through the pay-per-second API.

Commands
  run      Check inputs, read the video duration, upload local files, get a cost estimate
           and save a job plan. Nothing is charged unless you type "yes" at an interactive
           prompt. In a non-interactive shell it always stops after saving the plan.
  submit   Submit a saved plan (the paid step), then poll and download the result.
  resume   Keep polling a request that was already submitted and download the result.
           Never submits anything.
  status   Print the current status of a request once.
  cancel   Cancel a request that is still queued (canceled requests are refunded).

Docs this follows:
  https://docs.higgsfield.ai/docs/models/genjutsu/motion-transfer
  https://docs.higgsfield.ai/docs/models/genjutsu/object-swap
  https://docs.higgsfield.ai/docs/concepts/file-uploads
  https://docs.higgsfield.ai/docs/concepts/requests
  https://docs.higgsfield.ai/docs/concepts/polling
  https://docs.higgsfield.ai/docs/concepts/idempotency
  https://docs.higgsfield.ai/docs/concepts/billing-and-retention

Credentials come from HF_API_KEY_ID and HF_API_KEY_SECRET. They are only ever sent to
api.higgsfield.ai and are never printed or written to disk. Standard library only;
ffprobe is used to read the video when it is installed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import math
import os
import random
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

API_BASE = "https://api.higgsfield.ai"
API_HOST = "api.higgsfield.ai"
SKILL_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SKILL_DIR / "config.json"
USER_AGENT = "genjutsu-skill/1.0"

MODELS = {
    "motion-transfer": "higgsfield/genjutsu/motion-transfer/v1.0",
    "object-swap": "higgsfield/genjutsu/object-swap/v1.0",
}
RESOLUTIONS = ("1080p", "720p", "480p")  # highest first
MIN_SECONDS = 4.0
MAX_SECONDS = 30.0  # longer sources are trimmed to their first 30 s
MIN_IMAGES, MAX_IMAGES = 1, 8
MAX_PROMPT_CHARS = 10_000
MAX_URL_CHARS = 2083
OBJECT_SWAP_MIN_PIXELS = 409_600  # width x height of each frame
VIDEO_CONTENT_TYPES = {".mp4": "video/mp4", ".m4v": "video/mp4"}
IMAGE_CONTENT_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
}
TERMINAL_STATUSES = {"completed", "failed", "nsfw", "canceled"}
OUTPUT_KEYS = ("video", "zip", "mov", "jsx", "fbx", "ply")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PROBE_DOWNLOAD_LIMIT = 1 << 30  # 1 GiB, only used when ffprobe is missing for a URL source

EXIT_ERROR, EXIT_AMBIGUOUS, EXIT_POLL_STOPPED, EXIT_INTERRUPTED = 1, 2, 3, 130

# Network failures that leave the outcome unknown and are safe to retry for reads.
TRANSIENT_ERRORS = (OSError, http.client.HTTPException, ValueError)

SUBMIT_ERROR_HINTS = {
    400: "invalid parameters, rejected input, or your concurrency limit is reached "
    "(wait for running jobs to finish)",
    401: "credentials missing or invalid; check HF_API_KEY_ID and HF_API_KEY_SECRET",
    403: "insufficient credits; top up the API balance at https://console.higgsfield.ai",
    404: "model not found for this account",
    422: "request validation failed",
    423: "model temporarily blocked; try again later",
    503: "model disabled or not ready; try again later",
}


class ApiError(Exception):
    def __init__(self, status: int, detail: str, correlation_id: str | None = None):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail
        self.correlation_id = correlation_id


class ProbeError(Exception):
    pass


class UploadError(Exception):
    pass


class PollStopped(Exception):
    pass


# --------------------------------------------------------------------------- helpers


def die(msg: str, code: int = EXIT_ERROR):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def warn(msg: str):
    print(f"warning: {msg}", file=sys.stderr)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def usd(amount: float) -> str:
    return f"${amount:,.2f}"


def script_cmd() -> str:
    return f"python3 {shlex.quote(str(Path(__file__).resolve()))}"


def is_url(s: str) -> bool:
    return urllib.parse.urlsplit(s).scheme in ("http", "https")


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        die(f"missing config file {CONFIG_PATH}")
    except json.JSONDecodeError as e:
        die(f"{CONFIG_PATH} is not valid JSON: {e}")


def price_per_second(cfg: dict, mode: str, resolution: str) -> float | None:
    try:
        rate = cfg["price_usd_per_second"][mode][resolution]
    except (KeyError, TypeError):
        return None
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
        return None
    return float(rate)


def billed_seconds(duration: float) -> int:
    # Docs: sources over 30 s are trimmed, then duration is rounded up to whole seconds.
    return math.ceil(min(duration, MAX_SECONDS))


def auth_header() -> str:
    key_id = os.environ.get("HF_API_KEY_ID", "").strip()
    secret = os.environ.get("HF_API_KEY_SECRET", "").strip()
    missing = [n for n, v in (("HF_API_KEY_ID", key_id), ("HF_API_KEY_SECRET", secret)) if not v]
    if missing:
        die(f"set {' and '.join(missing)} in your environment (values are never printed or stored)")
    return f"Key {key_id}:{secret}"


def save_plan(plan: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(plan, indent=2) + "\n")
    tmp.replace(path)


def api_url(plan: dict, key: str, suffix: str) -> str:
    """Prefer the URL Higgsfield returned; fall back to the documented path for the request."""
    url = plan.get(key)
    if url and url.startswith("https://") and urllib.parse.urlsplit(url).hostname == API_HOST:
        return url
    return f"{API_BASE}/requests/{plan['request_id']}/{suffix}"


# --------------------------------------------------------------------------- HTTP


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Authenticated calls never follow redirects, so the key cannot be forwarded elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_api_opener = urllib.request.build_opener(_NoRedirect)


def _error_detail(raw: bytes) -> str:
    try:
        detail = json.loads(raw).get("detail")
    except Exception:
        detail = None
    if detail is None:
        return raw.decode(errors="replace").strip()[:500] or "(no body)"
    return detail if isinstance(detail, str) else json.dumps(detail)


def api_request(method: str, url: str, auth: str, body=None, idempotency_key=None, timeout=60):
    if not url.startswith("https://") or urllib.parse.urlsplit(url).hostname != API_HOST:
        raise ValueError(f"refusing to send credentials to {url}")
    headers = {"Authorization": auth, "Accept": "application/json", "User-Agent": USER_AGENT}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _api_opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, _error_detail(e.read()), e.headers.get("X-Correlation-ID")) from None
    return json.loads(raw) if raw.strip() else None


def download(url: str, dest: Path, max_bytes: int | None = None, attempts: int = 4) -> int:
    """Download without credentials (output and source URLs are public). Returns bytes written."""
    tmp = dest.with_name(dest.name + ".part")
    try:
        for attempt in range(1, attempts + 1):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as f:
                    expected = resp.headers.get("Content-Length")
                    written = 0
                    while True:
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if max_bytes and written > max_bytes:
                            raise ProbeError(f"file is larger than {max_bytes} bytes")
                        f.write(chunk)
                if expected and int(expected) != written:
                    raise OSError(f"incomplete download ({written} of {expected} bytes)")
                tmp.replace(dest)
                return written
            except urllib.error.HTTPError as e:
                if e.code < 500 or attempt == attempts:
                    raise
            except (OSError, http.client.HTTPException):
                if attempt == attempts:
                    raise
            time.sleep(2**attempt)
    finally:
        tmp.unlink(missing_ok=True)
    raise AssertionError("unreachable")


def upload_file(path: Path, content_type: str, auth: str) -> str:
    """Upload a local file via a presigned URL and return its public URL."""
    info = api_request(
        "POST", f"{API_BASE}/files/generate-upload-url", auth, body={"content_type": content_type}
    )
    if not isinstance(info, dict) or not info.get("upload_url") or not info.get("public_url"):
        raise UploadError(f"unexpected upload-URL response {json.dumps(info)[:200]}")
    upload_url, public_url = info["upload_url"], info["public_url"]
    headers = {str(k): str(v) for k, v in (info.get("upload_headers") or {}).items()}
    headers.setdefault("Content-Type", content_type)
    headers["Content-Length"] = str(path.stat().st_size)
    for attempt in range(1, 4):
        try:
            with path.open("rb") as f:
                # No Authorization header: the docs say never send credentials to storage.
                req = urllib.request.Request(upload_url, data=f, method="PUT", headers=headers)
                with urllib.request.urlopen(req, timeout=300) as resp:
                    resp.read()
            return public_url
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == 3:
                raise UploadError(
                    f"storage rejected {path.name}: HTTP {e.code} {_error_detail(e.read())}"
                ) from None
        except (OSError, http.client.HTTPException) as e:
            if attempt == 3:
                raise UploadError(f"upload of {path.name} failed: {e}") from None
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


# --------------------------------------------------------------------------- video probing


def probe_video(src: str, local: bool) -> tuple[float, int | None, int | None, str]:
    """Return (duration_s, width, height, method). width/height are None when unknown."""
    errors = []
    if shutil.which("ffprobe"):
        try:
            return (*_ffprobe(src), "ffprobe")
        except Exception as e:
            errors.append(f"ffprobe: {e}")
    try:
        if local:
            return (*_mp4_probe(Path(src)), "mp4 header")
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "source"
            download(src, copy, max_bytes=PROBE_DOWNLOAD_LIMIT)
            return (*_mp4_probe(copy), "mp4 header (downloaded)")
    except Exception as e:
        errors.append(f"mp4 header: {e}")
    raise ProbeError("; ".join(errors))


def _ffprobe(src: str) -> tuple[float, int | None, int | None]:
    proc = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0",
         "-show_entries", "format=duration:stream=width,height,duration",
         "-of", "json", src],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise ValueError(proc.stderr.strip() or f"exit code {proc.returncode}")
    info = json.loads(proc.stdout)
    stream = (info.get("streams") or [{}])[0]
    duration = info.get("format", {}).get("duration") or stream.get("duration")
    if duration in (None, "N/A"):
        raise ValueError("no duration reported")
    width, height = stream.get("width"), stream.get("height")
    return float(duration), (int(width) if width else None), (int(height) if height else None)


def _boxes(f, start: int, end: int):
    """Yield (type, payload_start, payload_end) for the ISO-BMFF boxes in [start, end)."""
    pos = start
    while pos + 8 <= end:
        f.seek(pos)
        size, kind = struct.unpack(">I4s", f.read(8))
        header = 8
        if size == 1:
            size = struct.unpack(">Q", f.read(8))[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header:
            return
        yield kind, pos + header, min(pos + size, end)
        pos += size


def _find_box(f, start: int, end: int, kind: bytes):
    for k, s, e in _boxes(f, start, end):
        if k == kind:
            return s, e
    return None


def _mp4_probe(path: Path) -> tuple[float, int | None, int | None]:
    """Read duration (mvhd) and the largest track size (tkhd) from an MP4 without ffprobe."""
    with path.open("rb") as f:
        end = f.seek(0, os.SEEK_END)
        moov = _find_box(f, 0, end, b"moov")
        if not moov:
            raise ValueError("no moov box; not a readable MP4")
        mvhd = _find_box(f, *moov, b"mvhd")
        if not mvhd:
            raise ValueError("no mvhd box")
        f.seek(mvhd[0])
        version = f.read(4)[0]
        if version == 1:
            f.seek(16, os.SEEK_CUR)
            timescale, units = struct.unpack(">IQ", f.read(12))
        else:
            f.seek(8, os.SEEK_CUR)
            timescale, units = struct.unpack(">II", f.read(8))
        if not timescale:
            raise ValueError("timescale is 0")
        width = height = None
        for kind, s, e in _boxes(f, *moov):
            if kind != b"trak":
                continue
            tkhd = _find_box(f, s, e, b"tkhd")
            if not tkhd:
                continue
            f.seek(tkhd[0])
            version = f.read(4)[0]
            # times, track id, reserved, duration; then reserved, layer, group, volume, matrix
            f.seek((32 if version == 1 else 20) + 16 + 36, os.SEEK_CUR)
            w, h = struct.unpack(">II", f.read(8))
            w, h = round(w / 65536), round(h / 65536)
            if w * h > (width or 0) * (height or 0):
                width, height = w, h
        return units / timescale, width, height


# --------------------------------------------------------------------------- plan display


def media_label(m: dict) -> str:
    if m["local"]:
        state = "uploaded" if m.get("public_url") else "local file, not uploaded yet"
        return f"{m['source']}  ({state})"
    return m["source"]


def plan_cost(plan: dict) -> float:
    """The higher of the list-price estimate and the server quote."""
    est = plan["estimate"]
    server = est.get("server") or {}
    try:
        server_usd = float(server.get("usd"))
    except (TypeError, ValueError):
        server_usd = 0.0
    return max(est["usd"], server_usd)


def print_summary(plan: dict, cfg: dict | None = None):
    v, est, inp, body = plan["video_info"], plan["estimate"], plan["inputs"], plan["body"]
    res, rate, billed = body["resolution"], est["usd_per_second"], est["billed_seconds"]
    dims = f", {v['width']}x{v['height']}" if v.get("width") else ""
    prompt = body.get("prompt", "")
    if len(prompt) > 160:
        prompt = f"{prompt[:160]}... ({len(prompt)} chars)"
    lines = [
        "",
        f"=== Genjutsu {plan['mode']}: cost check ===",
        f"Endpoint      POST {plan['endpoint']}",
        f"Source video  {media_label(inp['video'])}",
        f"Duration      {v['duration_s']:.2f} s{dims}  (read via {v['method']})",
    ]
    if v["duration_s"] > MAX_SECONDS:
        lines.append("              longer than 30 s: Higgsfield only uses the first 30 s")
    lines.append(f"Billed        {billed} s  (rounded up to whole seconds)")
    lines.append(f"References    {len(inp['images'])} image(s)")
    lines += [f"              {i}. {media_label(m)}" for i, m in enumerate(inp["images"], 1)]
    lines.append(f"Prompt        {prompt or '(none)'}")
    lines.append(f"Resolution    {res}")
    if plan.get("webhook"):
        lines.append(f"Webhook       {plan['webhook']}")
    lines.append(f"Rate          ${rate}/s at {res} (list price in config.json, before discounts)")
    lines.append(f"ESTIMATE      {usd(est['usd'])}  ({billed} s x ${rate})")
    server = est.get("server")
    if server is None:
        lines.append("Server quote  (not requested in a dry run)")
    elif "error" in server:
        lines.append(f"Server quote  unavailable ({server['error']}); relying on list price")
    else:
        lines.append(f"Server quote  ${server.get('usd')} ({server.get('credits')} credits) "
                     "from Higgsfield's estimate endpoint")
    if cfg:
        others = []
        for r in RESOLUTIONS:
            other_rate = price_per_second(cfg, plan["mode"], r)
            if r != res and other_rate:
                others.append(f"{r} {usd(billed * other_rate)}")
        if others:
            lines.append(f"Other tiers   {', '.join(others)}")
    print("\n".join(lines))


# --------------------------------------------------------------------------- commands


def classify(src: str, allowed: dict, label: str) -> dict:
    if is_url(src):
        if len(src) > MAX_URL_CHARS:
            die(f"{label} URL is longer than {MAX_URL_CHARS} characters")
        return {"source": src, "local": False}
    path = Path(src).expanduser()
    if not path.is_file():
        die(f"{label} not found: {src}")
    content_type = allowed.get(path.suffix.lower())
    if not content_type:
        kinds = ", ".join(sorted(allowed))
        hint = ""
        if allowed is VIDEO_CONTENT_TYPES:
            hint = (f" Convert it first, e.g.: ffmpeg -i {shlex.quote(src)} -c:v libx264 -crf 18 "
                    f"-c:a aac {shlex.quote(str(path.with_suffix('.mp4')))}")
        die(f"{label} {src}: Higgsfield uploads accept {kinds} for this input.{hint}")
    return {"source": str(path.resolve()), "local": True, "content_type": content_type}


def check_budget(amount: float, max_cost, what: str):
    if max_cost is not None and amount > float(max_cost):
        die(f"{what} {usd(amount)} is above the max cost {usd(float(max_cost))} "
            "(--max-cost / max_cost_usd in config.json). Nothing was submitted.")


def server_estimate(auth: str, model_id: str, body: dict) -> dict:
    """Ask Higgsfield's estimate endpoint (free, no generation). Best effort."""
    try:
        res = api_request("POST", f"{API_BASE}/estimate/{model_id}", auth, body=body)
    except ApiError as e:
        if e.status == 401:
            die("Higgsfield rejected the credentials (401); check HF_API_KEY_ID and HF_API_KEY_SECRET")
        return {"error": f"HTTP {e.status}: {e.detail}"}
    except TRANSIENT_ERRORS as e:
        return {"error": str(e)}
    if not isinstance(res, dict) or "usd" not in res:
        return {"error": f"unexpected response {json.dumps(res)[:200]}"}
    return {"usd": res.get("usd"), "credits": res.get("credits")}


def cmd_run(args) -> int:
    cfg = load_config()
    mode = args.mode
    model_id = MODELS[mode]
    resolution = args.resolution or cfg.get("default_resolution") or RESOLUTIONS[0]
    if resolution not in RESOLUTIONS:
        die(f"resolution must be one of {', '.join(RESOLUTIONS)}")

    prompt = args.prompt or ""
    if args.prompt_file:
        prompt = Path(args.prompt_file).expanduser().read_text().strip()
    if len(prompt) > MAX_PROMPT_CHARS:
        die(f"prompt is {len(prompt)} characters; the maximum is {MAX_PROMPT_CHARS}")
    if not MIN_IMAGES <= len(args.image) <= MAX_IMAGES:
        die(f"give {MIN_IMAGES}-{MAX_IMAGES} reference images (got {len(args.image)})")
    if args.webhook and (not args.webhook.startswith("https://") or len(args.webhook) > MAX_URL_CHARS):
        die("--webhook must be a public https:// URL")

    video = classify(args.video, VIDEO_CONTENT_TYPES, "source video")
    images = [classify(i, IMAGE_CONTENT_TYPES, "reference image") for i in args.image]

    try:
        duration, width, height, method = probe_video(video["source"], video["local"])
        if args.duration:
            warn(f"ignoring --duration; measured {duration:.2f} s from the file")
    except ProbeError as e:
        if not args.duration:
            die(f"could not read the video duration ({e}). "
                "Install ffprobe (ffmpeg) or pass --duration SECONDS.")
        duration, width, height, method = args.duration, None, None, "--duration (manual)"

    if duration < MIN_SECONDS:
        die(f"source video is {duration:.2f} s; Genjutsu needs at least {MIN_SECONDS:.0f} s")
    if duration > MAX_SECONDS:
        warn(f"source video is {duration:.2f} s; Higgsfield trims it to the first 30 s")
    if mode == "object-swap":
        if width and height:
            if width * height < OBJECT_SWAP_MIN_PIXELS:
                die(f"object swap needs at least {OBJECT_SWAP_MIN_PIXELS:,} pixels per frame; "
                    f"this video is {width}x{height} = {width * height:,}")
        else:
            warn(f"could not read the frame size; object swap needs at least "
                 f"{OBJECT_SWAP_MIN_PIXELS:,} pixels per frame (e.g. 854x480 or larger)")

    rate = price_per_second(cfg, mode, resolution)
    if rate is None:
        die(f"no per-second price configured for {mode} at {resolution}. Ask for the current "
            f"price and set price_usd_per_second.{mode}.{resolution} in {CONFIG_PATH}")
    billed = billed_seconds(duration)
    estimate = billed * rate
    max_cost = args.max_cost if args.max_cost is not None else cfg.get("max_cost_usd")
    check_budget(estimate, max_cost, "estimated cost")

    out_dir = Path(args.output_dir or cfg.get("output_dir") or "outputs").expanduser().resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    idempotency_key = str(uuid.uuid4())
    plan_path = out_dir / "jobs" / f"{stamp}_{mode}_{idempotency_key[:8]}.json"
    plan = {
        "version": 1,
        "created_at": now_iso(),
        "mode": mode,
        "model_id": model_id,
        "endpoint": f"{API_BASE}/{model_id}",
        "webhook": args.webhook,
        "body": {},
        "idempotency_key": idempotency_key,
        "inputs": {"video": video, "images": images},
        "video_info": {"duration_s": round(duration, 3), "width": width, "height": height,
                       "method": method},
        "estimate": {"billed_seconds": billed, "usd_per_second": rate,
                     "usd": round(estimate, 4), "server": None},
        "output_dir": str(out_dir),
        "status": "planned",
        "submit_attempts": 0,
        "request_id": None,
    }

    def build_body(placeholder: bool) -> dict:
        def ref(m):
            if m.get("public_url"):
                return m["public_url"]
            return f"<upload of {Path(m['source']).name}>" if (m["local"] and placeholder) else m["source"]
        body = {"video_url": ref(video), "image_urls": [ref(m) for m in images],
                "resolution": resolution}
        if prompt:
            body["prompt"] = prompt
        return body

    if args.dry_run:
        plan["body"] = build_body(placeholder=True)
        print_summary(plan, cfg)
        print("\nRequest body that would be sent:")
        print(json.dumps(plan["body"], indent=2))
        print("\nDry run: nothing uploaded, nothing submitted, nothing charged.")
        return 0

    auth = auth_header()
    for m in [video, *images]:
        if m["local"]:
            size_mb = Path(m["source"]).stat().st_size / 1e6
            print(f"Uploading {Path(m['source']).name} ({size_mb:.1f} MB, {m['content_type']}) ...")
            try:
                m["public_url"] = upload_file(Path(m["source"]), m["content_type"], auth)
            except (ApiError, *TRANSIENT_ERRORS) as e:
                die(f"could not upload {Path(m['source']).name}: {e}. Nothing was submitted.")
    plan["body"] = build_body(placeholder=False)

    plan["estimate"]["server"] = server_estimate(auth, model_id, plan["body"])
    check_budget(plan_cost(plan), max_cost, "estimate (higher of list price and server quote)")
    save_plan(plan, plan_path)
    print_summary(plan, cfg)
    print(f"\nPlan saved: {plan_path}")

    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            answer = input(f'\nType "yes" to submit this paid job (about {usd(plan_cost(plan))}): ')
        except EOFError:
            answer = ""
        if answer.strip().lower() == "yes":
            plan["confirmed_via"] = "interactive prompt"
            return submit_plan(plan, plan_path, auth, args.timeout_min, replay=False)
        print("Not submitted. Nothing has been charged.")
    else:
        print("\nNOT SUBMITTED. Nothing has been charged.")
    print(f"To submit exactly this job (the paid step):\n  {script_cmd()} submit {shlex.quote(str(plan_path))}")
    return 0


def submit_plan(plan: dict, plan_path: Path, auth: str, timeout_min: float, replay: bool) -> int:
    resume_hint = f"{script_cmd()} resume {shlex.quote(str(plan_path))}"
    if plan.get("request_id"):
        die(f"this plan was already submitted as request {plan['request_id']} and will not be "
            f"submitted again. To keep polling it: {resume_hint}")
    if plan.get("submit_attempts", 0) > 0 and not replay:
        die("an earlier submit of this plan ended without a confirmed response, so Higgsfield may "
            "have accepted it. Re-sending reuses the same Idempotency-Key, which per the "
            "Higgsfield docs returns the original request instead of creating a new one. "
            "If you want that, run submit again with --replay-same-key.")
    created = datetime.fromisoformat(plan["created_at"])
    age_h = (datetime.now(timezone.utc) - created).total_seconds() / 3600
    if age_h > 24:
        warn(f"this plan is {age_h:.0f} h old; temporary uploads may have expired. If the job "
             "fails it is not charged; run `run` again to re-upload.")

    previous_attempts = plan.get("submit_attempts", 0)
    plan["submit_attempts"] = previous_attempts + 1
    plan["last_submit_at"] = now_iso()
    plan.setdefault("confirmed_via", "submit command")
    save_plan(plan, plan_path)

    url = plan["endpoint"]
    if plan.get("webhook"):
        url += "?" + urllib.parse.urlencode({"hf_webhook": plan["webhook"]})
    if replay and previous_attempts:
        print(f"Replaying the earlier submit with the same Idempotency-Key {plan['idempotency_key']}")
    print(f"Submitting {plan['mode']} at {plan['body']['resolution']} "
          f"(estimate {usd(plan_cost(plan))}) ...")
    try:
        resp = api_request("POST", url, auth, body=plan["body"],
                           idempotency_key=plan["idempotency_key"], timeout=120)
    except ApiError as e:
        plan["last_error"] = {"status": e.status, "detail": e.detail,
                              "correlation_id": e.correlation_id, "at": now_iso()}
        if e.status < 500:
            # Rejected before acceptance: no request exists and the key was not consumed.
            plan["submit_attempts"] = previous_attempts
            plan["status"] = "rejected"
            save_plan(plan, plan_path)
            hint = SUBMIT_ERROR_HINTS.get(e.status, "request rejected")
            die(f"Higgsfield rejected the submission (HTTP {e.status}: {e.detail}). {hint}. "
                "No job was created and nothing was charged.")
        save_plan(plan, plan_path)
        return _ambiguous_submit(plan, plan_path, f"HTTP {e.status}: {e.detail}")
    except TRANSIENT_ERRORS as e:
        plan["last_error"] = {"detail": str(e), "at": now_iso()}
        save_plan(plan, plan_path)
        return _ambiguous_submit(plan, plan_path, str(e))

    if not isinstance(resp, dict) or not resp.get("request_id"):
        plan["last_error"] = {"detail": f"no request_id in response: {json.dumps(resp)[:300]}"}
        save_plan(plan, plan_path)
        return _ambiguous_submit(plan, plan_path, "response had no request_id")

    plan.update(
        request_id=resp["request_id"],
        status_url=resp.get("status_url"),
        cancel_url=resp.get("cancel_url"),
        status=resp.get("status", "queued"),
        submitted_at=now_iso(),
    )
    plan.pop("last_error", None)
    save_plan(plan, plan_path)
    print(f"Accepted. request_id: {plan['request_id']}")
    print(f"If this process stops, the job keeps running. Resume with:\n  {resume_hint}")
    return poll_and_finish(plan, plan_path, auth, timeout_min)


def _ambiguous_submit(plan: dict, plan_path: Path, reason: str) -> int:
    print(
        f"\nSubmission outcome UNKNOWN ({reason}).\n"
        "The job may or may not have been accepted. It was NOT retried automatically.\n"
        "Re-sending this plan reuses its Idempotency-Key, so per the Higgsfield docs an accepted\n"
        "job is returned rather than duplicated. Only if you want that:\n"
        f"  {script_cmd()} submit {shlex.quote(str(plan_path))} --replay-same-key\n"
        "You can also check request history at https://console.higgsfield.ai",
        file=sys.stderr,
    )
    return EXIT_AMBIGUOUS


def poll(auth: str, status_url: str, timeout_s: float) -> dict:
    """Poll one request until it reaches a terminal status. Never submits anything."""
    start = time.monotonic()
    delay, err_delay, last_status, last_print = 2.0, 2.0, None, 0.0
    while True:
        elapsed = time.monotonic() - start
        clock = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        failure = None
        try:
            result = api_request("GET", status_url, auth, timeout=30)
            if not isinstance(result, dict) or "status" not in result:
                raise ValueError(f"unexpected status response {json.dumps(result)[:200]}")
        except ApiError as e:
            if e.status == 401:
                raise PollStopped("credentials rejected (401) while polling; fix them, then resume")
            if e.status == 404:
                raise PollStopped("request not found (404); check the request id and account")
            failure = str(e)
        except TRANSIENT_ERRORS as e:
            failure = str(e) or type(e).__name__
        if failure:
            wait = err_delay
            err_delay = min(err_delay * 2, 60.0)
            print(f"[{clock}] status check failed ({failure}); polling the same request again "
                  f"in {wait:.0f}s", file=sys.stderr)
        else:
            err_delay = 2.0
            status = result["status"]
            if status in TERMINAL_STATUSES:
                print(f"[{clock}] {status}")
                return result
            if status != last_status or elapsed - last_print >= 60:
                print(f"[{clock}] {status}")
                last_status, last_print = status, elapsed
            wait = delay
            delay = min(delay * 1.5, 10.0)
        if elapsed + wait > timeout_s:
            raise PollStopped(f"not finished after {timeout_s / 60:.0f} min")
        time.sleep(wait + random.uniform(0, 0.5))


def download_outputs(plan: dict, result: dict) -> dict:
    out_dir = Path(plan.get("output_dir") or "outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    previous = plan.get("outputs") or {}
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"genjutsu_{plan.get('mode', 'request')}_{stamp}_{plan['request_id'][:8]}"
    saved = {}
    for key in OUTPUT_KEYS:
        item = result.get(key)
        url = item.get("url") if isinstance(item, dict) else None
        if not url:
            continue
        old = previous.get(key) or {}
        if old.get("path") and Path(old["path"]).is_file():
            saved[key] = old
            continue
        ext = Path(urllib.parse.urlsplit(url).path).suffix
        if not re.fullmatch(r"\.[A-Za-z0-9]{1,5}", ext):
            ext = ".mp4" if key == "video" else f".{key}"
        dest = out_dir / f"{base}{'' if key == 'video' else '_' + key}{ext}"
        print(f"Downloading {key} -> {dest}")
        try:
            saved[key] = {"url": url, "path": str(dest), "bytes": download(url, dest)}
        except Exception as e:
            saved[key] = {"url": url, "path": None, "error": str(e)}
            warn(f"could not download {key}: {e}")
    return saved


def poll_and_finish(plan: dict, plan_path: Path, auth: str, timeout_min: float) -> int:
    resume_hint = f"{script_cmd()} resume {shlex.quote(str(plan_path))}"
    try:
        result = poll(auth, api_url(plan, "status_url", "status"), timeout_min * 60)
    except KeyboardInterrupt:
        print(f"\nStopped polling. The job keeps running on Higgsfield; nothing was resubmitted.\n"
              f"Resume with:\n  {resume_hint}", file=sys.stderr)
        return EXIT_INTERRUPTED
    except PollStopped as e:
        print(f"\nStopped polling: {e}. Nothing was resubmitted.\nResume with:\n  {resume_hint}",
              file=sys.stderr)
        return EXIT_POLL_STOPPED

    status = result["status"]
    plan.update(status=status, final_response=result, finished_at=now_iso())
    save_plan(plan, plan_path)
    rid = plan["request_id"]
    if status == "completed":
        plan["outputs"] = download_outputs(plan, result)
        save_plan(plan, plan_path)
        ok = True
        print(f"\nDone. request_id: {rid}")
        for key, out in plan["outputs"].items():
            if out.get("path"):
                print(f"{key} saved to: {out['path']}")
            else:
                ok = False
                print(f"{key} NOT downloaded ({out.get('error')}); retry with: {resume_hint}")
            print(f"{key} URL:      {out['url']}  (kept by Higgsfield for at least 7 days)")
        if not plan["outputs"]:
            ok = False
            print(f"Completed, but the response had no output URL: {json.dumps(result)}")
        return 0 if ok else EXIT_ERROR
    if status == "failed":
        print(f"\nJob failed: {result.get('error') or 'no error message'} (request_id {rid}).")
    elif status == "nsfw":
        print(f"\nJob rejected by content moderation (nsfw) (request_id {rid}).")
    else:
        print(f"\nJob ended with status {status} (request_id {rid}).")
    print("Per the Higgsfield docs, failed, nsfw and canceled requests are not charged. "
          "Nothing was resubmitted; starting over is a new paid job via `run`.")
    return EXIT_ERROR


def load_target(target: str, output_dir: str | None) -> tuple[dict, Path]:
    """Accept a plan file or a bare request id. Never creates a generation request."""
    path = Path(target).expanduser()
    if path.is_file():
        try:
            return json.loads(path.read_text()), path
        except json.JSONDecodeError as e:
            die(f"{path} is not a valid plan file: {e}")
    if not UUID_RE.fullmatch(target):
        die(f"{target} is neither a plan file nor a request id")
    cfg = load_config()
    out_dir = Path(output_dir or cfg.get("output_dir") or "outputs").expanduser().resolve()
    jobs = out_dir / "jobs"
    for f in sorted(jobs.glob("*.json")) if jobs.is_dir() else []:
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("request_id") == target:
            return data, f
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        "version": 1,
        "created_at": now_iso(),
        "mode": "request",
        "note": "record created by resume/status/cancel for a request id without a saved plan",
        "request_id": target,
        "output_dir": str(out_dir),
        "submit_attempts": 1,
        "status": "unknown",
    }, jobs / f"{stamp}_request_{target[:8]}.json"


def require_submitted(plan: dict, plan_path: Path):
    if plan.get("request_id"):
        return
    if plan.get("submit_attempts", 0) > 0:
        die("this plan has no request id because its submit outcome was unknown. To recover it "
            f"safely: {script_cmd()} submit {shlex.quote(str(plan_path))} --replay-same-key")
    die(f"this plan was never submitted. To submit it: "
        f"{script_cmd()} submit {shlex.quote(str(plan_path))}")


def cmd_submit(args) -> int:
    plan, plan_path = load_target(args.plan, None)
    if "body" not in plan or "estimate" not in plan:
        die(f"{plan_path} is not a plan created by `run`")
    print_summary(plan, load_config())
    return submit_plan(plan, plan_path, auth_header(), args.timeout_min, replay=args.replay_same_key)


def cmd_resume(args) -> int:
    plan, plan_path = load_target(args.target, args.output_dir)
    require_submitted(plan, plan_path)
    save_plan(plan, plan_path)
    print(f"Polling request {plan['request_id']} (no new request will be created) ...")
    return poll_and_finish(plan, plan_path, auth_header(), args.timeout_min)


def cmd_status(args) -> int:
    plan, plan_path = load_target(args.target, args.output_dir)
    require_submitted(plan, plan_path)
    try:
        result = api_request("GET", api_url(plan, "status_url", "status"), auth_header(), timeout=30)
    except ApiError as e:
        die(f"status check failed: {e}")
    print(json.dumps(result, indent=2))
    return 0


def cmd_cancel(args) -> int:
    plan, plan_path = load_target(args.target, args.output_dir)
    require_submitted(plan, plan_path)
    try:
        api_request("POST", api_url(plan, "cancel_url", "cancel"), auth_header(), timeout=30)
    except ApiError as e:
        if e.status == 400:
            die("the request has already started processing and can no longer be canceled")
        die(f"cancel failed: {e}")
    plan.update(status="canceled", canceled_at=now_iso())
    save_plan(plan, plan_path)
    print(f"Canceled request {plan['request_id']}. Canceled queued requests are refunded.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Higgsfield Genjutsu via the pay-per-second API (motion transfer, object swap).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Flow: run (plan + cost check, no charge) -> confirm -> submit <plan> (paid) "
               "-> resume <plan> if polling stops.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="plan a job: probe, upload, estimate (no charge)")
    run.add_argument("--video", required=True, help="source video: local .mp4 or public URL (min 4 s)")
    run.add_argument("--image", required=True, action="extend", nargs="+",
                     help="reference image(s): local jpg/png/webp/gif or URLs, 1-8 total, in order")
    prompt = run.add_mutually_exclusive_group()
    prompt.add_argument("--prompt", help="optional text instructions (max 10000 chars)")
    prompt.add_argument("--prompt-file", help="read the prompt from a text file")
    run.add_argument("--mode", choices=sorted(MODELS), default="motion-transfer",
                     help="motion-transfer (recast the shot, default) or object-swap "
                          "(swap elements, keep the rest)")
    run.add_argument("--resolution", choices=RESOLUTIONS,
                     help="output tier; default from config.json (1080p)")
    run.add_argument("--webhook", help="optional https URL for Higgsfield's completion webhook")
    run.add_argument("--max-cost", type=float, help="refuse if the estimate is above this many USD")
    run.add_argument("--duration", type=float,
                     help="source duration in seconds, used only if it cannot be read from the file")
    run.add_argument("--output-dir", help="where results and job plans go (default ./outputs)")
    run.add_argument("--dry-run", action="store_true",
                     help="estimate only: no uploads, no API calls, no credentials needed")
    run.add_argument("--timeout-min", type=float, default=90,
                     help="stop polling after this many minutes (job keeps running; resume later)")
    run.set_defaults(func=cmd_run)

    submit = sub.add_parser("submit", help="submit a saved plan (paid), poll, download")
    submit.add_argument("plan", help="plan file written by `run`")
    submit.add_argument("--replay-same-key", action="store_true",
                        help="re-send after an unknown outcome, reusing the plan's Idempotency-Key")
    submit.add_argument("--timeout-min", type=float, default=90)
    submit.set_defaults(func=cmd_submit)

    for name, func, text in (
        ("resume", cmd_resume, "keep polling a submitted request and download the result"),
        ("status", cmd_status, "print a request's current status once"),
        ("cancel", cmd_cancel, "cancel a request that is still queued"),
    ):
        sp = sub.add_parser(name, help=text)
        sp.add_argument("target", help="plan file or request id")
        sp.add_argument("--output-dir", help="where to look for plans / save results (default ./outputs)")
        if name == "resume":
            sp.add_argument("--timeout-min", type=float, default=90)
        sp.set_defaults(func=func)
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except UploadError as e:
        die(f"{e}. Nothing was submitted.")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
