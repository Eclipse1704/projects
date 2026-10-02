<?php if (!defined('ABSPATH')) exit; ?>
<div class="wrap"><div id="nps-app" dir="rtl">
  <header class="top"><div class="in">
    <h1 class="title"><i aria-hidden="true"></i>סורק מוצרים</h1>
    <button id="tab" class="tab" type="button"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg><span>הגדרות</span></button>
  </div></header>
  <div class="brand"></div>

  <main id="home" class="wrap">
    <section id="keyCard" class="card key" hidden>
      <p class="label">צעד אחד לפני שמתחילים</p>
      <p>מדביקים מפתח API של Claude. יוצרים אותו ב-<a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">console.anthropic.com</a> ← Create Key.</p>
      <input id="key" type="password" placeholder="sk-ant-..." autocomplete="off">
      <button id="saveKey" class="primary" type="button">שמור מפתח</button>
      <p id="keyMsg" class="msg" role="status"></p>
    </section>

    <section class="card">
      <p class="label">קישורים למוצרים</p>
      <p class="hint">אחד או הרבה, מכל אתר. כל מוצר נכנס לחנות כטיוטה, עם תמונות, קטלוג, ספר הוראות וסרטון מאתר היצרן.</p>
      <textarea id="links" placeholder="https://..."></textarea>
      <button id="start" class="primary" type="button"><svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 0l8 5-8 5z"/></svg>התחל</button>
      <p id="msg" class="msg" role="status"></p>
    </section>

    <div id="run" class="run"></div>
    <div id="worker" class="worker"></div>
    <div id="summary" class="summary"></div>
    <div id="list" class="list" aria-live="polite"></div>
    <div class="foot" style="padding:0; gap:18px">
      <button id="export" class="link" type="button" hidden>הורד טבלה (CSV)</button>
      <button id="clear" class="link" type="button" hidden>נקה מוצרים שהסתיימו מהרשימה</button>
      <button id="stop" class="link danger" type="button" hidden>עצור הכל</button>
    </div>
  </main>

  <main id="settingsView" class="wrap" hidden>
    <section class="card">
      <div class="grid2">
        <div class="field">
          <label>מהירות</label>
          <div class="seg" data-key="fast">
            <button type="button" data-v="yes">מהיר<small>מוכן תוך דקות · כ-0.4$ למוצר</small></button>
            <button type="button" data-v="no">חסכוני<small>עד שעה · כ-0.2$ למוצר</small></button>
          </div>
        </div>
        <div class="field">
          <label>מודל</label>
          <div class="seg" data-key="model">
            <button type="button" data-v="claude-sonnet-5">Sonnet<small>מומלץ</small></button>
            <button type="button" data-v="claude-opus-5">Opus<small>חזק יותר · פי 2.5 במחיר</small></button>
          </div>
        </div>
        <div class="field">
          <label>מוצר חדש נכנס לחנות בתור</label>
          <div class="seg" data-key="publish_status">
            <button type="button" data-v="draft">טיוטה</button>
            <button type="button" data-v="pending">ממתין לסקירה</button>
          </div>
        </div>
        <div class="field">
          <label>מייל כשהסריקה מסתיימת</label>
          <div class="seg" data-key="email">
            <button type="button" data-v="yes">כן</button>
            <button type="button" data-v="no">לא</button>
          </div>
        </div>
      </div>
      <p id="siteInfo" class="sub"></p>
    </section>

    <section class="card">
      <div class="field">
        <label for="s-glossary">מילון מונחים</label>
        <p class="hint">שורה לכל מונח: אנגלית = איך אומרים אצלנו. מילה שיצאה לא טוב? מוסיפים אותה כאן.</p>
        <textarea id="s-glossary" class="tall" data-key="glossary"></textarea>
      </div>
      <div class="field">
        <label for="s-avoid">מילים שלא משתמשים בהן</label>
        <p class="hint">מילה או ביטוי בכל שורה. אם Claude משתמש באחד מהם, הטקסט חוזר אליו לתיקון.</p>
        <textarea id="s-avoid" class="rtl" data-key="avoid_words"></textarea>
      </div>
      <div class="field">
        <label for="s-style">מוצרים לדוגמה לסגנון</label>
        <p class="hint">ריק = Claude לומד מהמוצרים האחרונים שפורסמו בחנות. אפשר לשים כאן קישורים למוצרים מסוימים, אחד בכל שורה.</p>
        <textarea id="s-style" data-key="style_urls" placeholder="(אוטומטי)"></textarea>
      </div>
      <details><summary>שדות מתקדמים: איפה החנות שומרת קטלוג, ספר הוראות ווידאו</summary>
        <p class="hint" style="margin:6px 0">ריק = מזוהה לבד ממוצרים קיימים.</p>
        <div class="grid2">
          <div class="field"><label>שדה "קטלוג pdf"</label><input data-key="field_catalog"></div>
          <div class="field"><label>שדה "ספר הוראות"</label><input data-key="field_manual"></div>
          <div class="field"><label>שדה "וידאו מוצר"</label><input data-key="field_video"></div>
        </div>
      </details>
    </section>

    <div class="row">
      <button id="saveSettings" class="primary" type="button">שמור הגדרות</button>
      <button id="back" class="ghost" type="button">חזרה</button>
    </div>
    <p id="setMsg" class="msg" role="status"></p>

    <section class="card">
      <p class="label">מפתח API של Claude</p>
      <p id="keyState" class="sub"></p>
      <input id="key2" type="password" placeholder="sk-ant-... (מפתח חדש)" autocomplete="off">
      <button id="saveKey2" class="ghost" type="button">החלף מפתח</button>
      <p id="keyMsg2" class="msg" role="status"></p>
    </section>
    <button id="reset" class="link" type="button" style="justify-self:start">החזר הגדרות ברירת מחדל</button>
  </main>
</div></div>
