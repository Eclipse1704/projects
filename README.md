# projects
Some bash scripts that i have made

## Supplier product scraper (קטלוג מוצרים בעברית)

כלי שסורק אתר ספק או יצרן ובונה לכל מוצר דף HTML בעברית, במבנה שנוח גם למודלי שפה (LLM):

- שם המוצר
- תיאור קצר (עד 80 מילים)
- תיאור מלא, כולל שימושים ומפרט טכני (עד 500 מילים)
- קישורים לסרטוני YouTube, רק אם הם מופיעים באתר היצרן הרשמי
- הורדה של 3-5 תמונות מאתר היצרן הרשמי, בשמות כמו `FOTRIC-226S-001.jpg`
- הורדה של ברושור ומדריך למשתמש (PDF) מאתר היצרן הרשמי
- קישורים לדף המוצר

הקוד נמצא ב-`.claude/skills/supplier-product-scraper/`, וההוראות המלאות ב-`SKILL.md` שבאותה תיקייה.

### שימוש עם Claude Code (הכי פשוט)

פותחים את התיקייה הזו ב-Claude Code וכותבים, למשל:
> תסרוק את כל המוצרים של https://www.example.com/products ותבנה קטלוג בעברית

Claude מפעיל את הסקיל, מוסיף את הספק לקובץ ההגדרות, סורק את האתר וכותב את הטקסטים בעברית.

### שימוש ידני מהטרמינל

```bash
cd .claude/skills/supplier-product-scraper/scripts
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...        # בשביל כתיבת הטקסטים בעברית
python run.py all                   # כל הספקים שב-suppliers.yaml
python run.py all --supplier fotric # ספק אחד בלבד
```
התוצאה נשמרת בתיקייה `output/`. כדי לראות את הקטלוג פותחים את `output/index.html` בדפדפן.

ספק חדש מוסיפים כבלוק חדש בקובץ `suppliers.yaml`. אפשר גם בלי לערוך את הקובץ:
```bash
python run.py all --manufacturer "Riezler" --url https://www.riezler.eu/en/products/push-systems --official-domain riezler.eu
```

ספקים שכבר מוגדרים: Jacobs-MC (Lixener30, MultiPro, Sniffer430, Vister), FOTRIC (כל המצלמות התרמיות), Riezler (Push systems), Mitcorp (X-series).
