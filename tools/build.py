"""Build one carousel for Notion.

  python3 tools/build.py stage specs/<id>.json      render, zip, copy to upload/<id>/<stamp>/, print a manifest
  python3 tools/build.py page specs/<id>.json ids.json   print the Notion page content (markdown) for the uploaded files
  python3 tools/build.py lock                       re-sign the locked design files (only after the owner approves a design change in chat)

ids.json maps "zip" and "01".."NN" to Notion file-upload IDs returned by create-attachment.
"""
import hashlib, json, shutil, sys, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = "https://raw.githubusercontent.com/Eclipse1704/projects/jacobs-ig-engine/"
sys.path.insert(0, str(ROOT))
import pro  # noqa: E402

CHANGE_NOTE = ('<callout icon="✍️" color="yellow_bg">\n<b>Want a change?</b> Write it in <b>Requested changes</b> at the top of this page '
               '(text or design, any language). Claude checks for requests every hour between 08:00 and 22:00 Israel time, updates the slides and the caption '
               'on this page, writes what it changed in <b>Change log</b> and sets the status to <b>Updated – please review</b>. '
               'When the post is right, set the status to <b>Approved</b>.\n</callout>')


LOCKED = ["pro.py", "brand_pro.json", "DESIGN.md"]


def _digests():
    return {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in LOCKED}


def check_lock():
    """The design system is locked (DESIGN.md). Refuse to render if a locked file changed."""
    want = json.loads((ROOT / "design.lock").read_text())
    changed = [f for f, h in _digests().items() if want.get(f) != h]
    if changed:
        raise SystemExit("LOCKED design files changed: " + ", ".join(changed) +
                         ". The design is locked (see DESIGN.md). Revert them with `git checkout -- " + " ".join(changed) +
                         "`; only the owner can approve a design change, in chat.")


def make_zip(pngs, zip_path, folder):
    """Zip the slides as high-quality JPEGs: Notion's free plan takes files up to 5 MiB, and PNG slides add up to more."""
    from io import BytesIO
    from PIL import Image
    for q in (95, 92, 88, 84):
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as z:
            for p in pngs:
                buf = BytesIO()
                Image.open(p).convert("RGB").save(buf, "JPEG", quality=q, subsampling=0, optimize=True)
                z.writestr(f"{folder}/{p.stem}.jpg", buf.getvalue())
        if zip_path.stat().st_size < 4.7 * 1024 * 1024:
            return
    raise SystemExit("zip is still over 4.7 MiB")


def stage(spec_path):
    check_lock()
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    out = pro.render(spec_path, pro.load_brand(), ROOT / "out_pro")
    sid = spec["id"]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = ROOT / "upload" / sid / stamp
    shutil.rmtree(ROOT / "upload" / sid, ignore_errors=True)  # keep only the newest version in the branch
    dest.mkdir(parents=True)
    pngs = sorted(out.glob("[0-9][0-9].png"))
    zip_name = spec.get("notion", {}).get("zip_name") or f"{sid}.zip"
    folder = Path(zip_name).stem
    make_zip(pngs, dest / zip_name, folder)
    files = []
    for p in pngs:
        shutil.copy(p, dest / p.name)
        files.append({"key": p.stem, "filename": f"{sid}-{p.name}", "path": f"upload/{sid}/{stamp}/{p.name}", "size": p.stat().st_size})
    files.append({"key": "zip", "filename": zip_name, "path": f"upload/{sid}/{stamp}/{zip_name}", "size": (dest / zip_name).stat().st_size})
    for f in files:
        f["url"] = RAW + f["path"]
    man = {"id": sid, "stamp": stamp, "slides": len(pngs), "files": files, "caption": (out / "caption.txt").read_text(encoding="utf-8").strip()}
    (dest / "manifest.json").write_text(json.dumps(man, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(man, indent=1, ensure_ascii=False))


def page(spec_path, ids_path):
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    ids = json.loads(Path(ids_path).read_text(encoding="utf-8"))
    sid = spec["id"]
    out = ROOT / "out_pro" / sid
    n = len(spec["slides"])
    cap = (out / "caption.txt").read_text(encoding="utf-8").strip()
    parts = [CHANGE_NOTE]
    note = spec.get("notion", {}).get("note")
    if note:
        parts.append(f'<callout icon="📌" color="yellow_bg">\n{note}\n</callout>')
    parts.append(f'<callout icon="⬇️" color="blue_bg">\n<b>Download all {n} slides at once:</b> tap the file below → Save to Files. '
                 'In the Files app, tap it once to open the folder, then Select → Select All → Save Images.\n</callout>')
    parts.append(f'<file source="file-upload://{ids["zip"]}">\nAll {n} slides, numbered 01–{n:02d}\n</file>')
    parts.append('<callout icon="🖼️" color="gray_bg">\n<b>Or save them one by one, top to bottom:</b> tap a slide → share → Save Image. The caption is at the bottom.\n</callout>')
    for i in range(1, n + 1):
        parts.append(f'<image source="file-upload://{ids[f"{i:02d}"]}" />')
    parts += ["---", "### ✍️ Caption", "Tap the copy button on the box, then paste it in Instagram.", "```txt\n" + cap + "\n```",
              '<callout icon="✅" color="green_bg">\nPosted? Tick <b>Posted</b> at the top of this page.\n</callout>']
    print("\n\n".join(parts))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "stage":
        stage(sys.argv[2])
    elif cmd == "page":
        page(sys.argv[2], sys.argv[3])
    elif cmd == "lock":
        (ROOT / "design.lock").write_text(json.dumps(_digests(), indent=1) + "\n")
        print("design.lock updated")
    else:
        raise SystemExit(__doc__)
