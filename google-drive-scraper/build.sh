#!/bin/sh
# Builds install/Code.gs: all script files in one, so installing means copying 2 files.
cd "$(dirname "$0")"
{
  echo "// סורק מוצרים ל-Google Drive - כל הקוד בקובץ אחד."
  echo "// מדביקים את כל הקובץ הזה ב-Code.gs בעורך של Apps Script. הוראות: README.md"
  for f in Settings.gs Extract.gs Claude.gs Output.gs Main.gs; do
    echo ""
    echo "// ======================================== $f ========================================"
    cat "$f"
  done
} > install/Code.gs
cp appsscript.json install/appsscript.json
