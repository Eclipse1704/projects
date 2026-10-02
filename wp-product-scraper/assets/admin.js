/* סורק מוצרים - the screen. Talks to the plugin's REST API (NPS.root). */
(function () {
  var $ = function (id) { return document.getElementById(id); };
  if (!$('nps-app')) return;
  var timer = null, stopArmed = false, last = null, fixOpen = {};
  var STEP_NAMES = ['יצרן', 'מקור', 'עברית', 'חנות'];
  var EDIT_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16z"/></svg>';
  var EYE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';

  function api(method, path, body) {
    return fetch(NPS.root + path, {
      method: method, credentials: 'same-origin',
      headers: { 'X-WP-Nonce': NPS.nonce, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json().then(function (j) { if (!r.ok) throw new Error(j && j.message || ('שגיאה ' + r.status)); return j; });
    });
  }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function shortLink(url) { return url.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, ''); }
  function guessName(url) {
    var last = url.split(/[?#]/)[0].replace(/\/+$/, '').split('/').pop() || url;
    try { last = decodeURIComponent(last); } catch (e) {}
    return last.replace(/\.(html?|php|aspx?)$/i, '').replace(/[-_+]+/g, ' ');
  }
  function say(el, text, good) { el.textContent = text || ''; el.className = 'msg ' + (good ? 'good' : 'bad'); }

  function stepsHtml(it) {
    var now = { 25: 0, 45: 1, 65: 2, 85: 3 }[it.pct];
    var finished = it.pct === 100 && (it.state === 'done' || it.state === 'warn');
    return '<div class="steps">' + STEP_NAMES.map(function (n, i) {
      var cls = finished || (now !== undefined && i < now) ? 'on' : (i === now ? 'now' : '');
      return '<span class="' + cls + '">' + n + '</span>';
    }).join('') + '</div>';
  }

  function render(state) {
    last = state;
    $('keyCard').hidden = state.hasKey;
    var items = state.items || [];
    var n = { done: 0, working: 0, other: 0 };
    items.forEach(function (it) { if (it.state === 'done' || it.state === 'warn') n.done++; else if (it.state === 'working') n.working++; else n.other++; });
    var w = state.worker || {};
    $('worker').className = 'worker' + (w.lastError ? ' bad' : '');
    $('worker').innerHTML = w.lastError ? '<b></b>תקלה בעבודה ברקע, המערכת מנסה שוב: ' + esc(w.lastError) : (w.running ? '<b></b>עובד ברקע. אפשר לסגור את הדף.' : '');
    $('run').innerHTML = items.length ? '<a href="' + esc(state.draftsUrl) + '">' + EDIT_ICON + 'כל הטיוטות בחנות</a>' +
      (+state.runCost > 0 ? '<span class="cost">עלות ההרצה עד עכשיו: כ-' + esc(state.runCost) + '$</span>' : '') : '';
    $('summary').innerHTML = items.length ? (n.working ? '<span class="chip run">' + n.working + ' בעבודה</span>' : '') +
      (n.done ? '<span class="chip ok">' + n.done + ' מוכנים</span>' : '') + (n.other ? '<span class="chip">' + n.other + ' אחרים</span>' : '') : '';
    if (!items.length) {
      $('list').innerHTML = '<div class="empty">עוד אין מוצרים.<br>מדביקים קישורים ולוחצים "התחל".</div>';
    } else {
      $('list').innerHTML = items.map(function (it) {
        var finished = it.state === 'done' || it.state === 'warn';
        var box = fixOpen[it.id];
        return '<article class="item ' + it.state + '">' +
          '<div class="head"><div class="dot" aria-hidden="true">' + ({ done: '✓', warn: '!', error: '×' }[it.state] || '') + '</div><div>' +
            '<div class="name">' + esc(it.name || guessName(it.link)) + '</div>' +
            '<div class="meta" title="' + esc(it.link) + '">' + esc(it.manufacturer ? it.manufacturer + ' · ' + shortLink(it.link) : shortLink(it.link)) + '</div>' +
          '</div></div>' +
          (it.state === 'working' || finished ? stepsHtml(it) : '') +
          '<div class="actions"><span class="state">' + esc(it.step) + (it.cost && finished ? ' <span class="icost">· כ-' + esc(it.cost) + '$</span>' : '') + '</span>' +
            '<span class="btns">' +
            (it.canFix ? '<button class="fixbtn" type="button" data-fix="' + it.id + '">✏️ תקן טקסט</button>' : '') +
            (it.viewUrl && finished ? '<a class="open" href="' + esc(it.viewUrl) + '" target="_blank" rel="noopener">' + EYE_ICON + 'תצוגה מקדימה</a>' : '') +
            (it.editUrl ? '<a class="open site" href="' + esc(it.editUrl) + '">' + EDIT_ICON + 'עריכה ופרסום</a>' : '') +
          '</span></div>' +
          (box ? '<div class="fix" data-box="' + it.id + '"><textarea placeholder="מה לתקן? למשל: לקצר את התיאור הקצר, להדגיש את העמידות למים, לכתוב מצלמה תרמית ולא מצלמת חום">' + esc(box.text) + '</textarea>' +
            '<div class="row"><button class="primary" type="button" data-send="' + it.id + '">שלח לתיקון</button><button class="ghost" type="button" data-cancel="' + it.id + '">ביטול</button></div>' +
            '<p class="msg' + (box.bad ? ' bad' : ' good') + '">' + esc(box.msg || '') + '</p></div>' : '') +
          (it.notes ? '<details><summary>' + (it.state === 'error' ? 'מה קרה?' : 'מה חסר?') + '</summary>' + esc(it.notes) + '</details>' : '') +
          '</article>';
      }).join('');
    }
    $('stop').hidden = !n.working;
    $('clear').hidden = !(items.length - n.working);
    $('export').hidden = !items.length;
    clearTimeout(timer);
    timer = setTimeout(refresh, n.working ? 5000 : 30000);
  }

  function refresh() {
    var a = document.activeElement;
    if (a && a.closest && a.closest('.fix')) { clearTimeout(timer); timer = setTimeout(refresh, 5000); return; }
    api('GET', 'state').then(render).catch(function () { clearTimeout(timer); timer = setTimeout(refresh, 15000); });
  }

  $('start').addEventListener('click', function () {
    var text = $('links').value;
    if (!text.trim()) { say($('msg'), 'מדביקים קודם קישורים בתיבה.'); return; }
    $('start').disabled = true;
    say($('msg'), 'מתחיל…', true);
    api('POST', 'start', { text: text }).then(function (r) {
      $('start').disabled = false;
      say($('msg'), r.message, r.ok);
      if (r.ok) $('links').value = '';
      if (r.needKey) $('keyCard').hidden = false;
      refresh();
    }).catch(function (e) { $('start').disabled = false; say($('msg'), 'משהו השתבש: ' + e.message); });
  });

  function saveKey(btn, input, msgEl, after) {
    btn.disabled = true;
    say(msgEl, 'בודק את המפתח…', true);
    api('POST', 'key', { key: input.value }).then(function (r) {
      btn.disabled = false; say(msgEl, r.message, r.ok);
      if (r.ok) { input.value = ''; after(); }
    }).catch(function (e) { btn.disabled = false; say(msgEl, 'משהו השתבש: ' + e.message); });
  }
  $('saveKey').addEventListener('click', function () { saveKey($('saveKey'), $('key'), $('keyMsg'), function () { setTimeout(refresh, 600); }); });
  $('saveKey2').addEventListener('click', function () { saveKey($('saveKey2'), $('key2'), $('keyMsg2'), loadSettings); });

  $('stop').addEventListener('click', function () {
    if (!stopArmed) {
      stopArmed = true;
      $('stop').textContent = 'בטוח? לחצו שוב לעצירה';
      setTimeout(function () { stopArmed = false; $('stop').textContent = 'עצור הכל'; }, 4000);
      return;
    }
    stopArmed = false;
    $('stop').textContent = 'עצור הכל';
    api('POST', 'stop').then(render);
  });
  $('clear').addEventListener('click', function () { api('POST', 'clear').then(render); });
  $('export').addEventListener('click', function () {
    api('GET', 'export').then(function (r) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([r.csv], { type: 'text/csv;charset=utf-8' }));
      a.download = 'סורק-מוצרים.csv';
      document.body.appendChild(a); a.click(); a.remove();
    });
  });

  $('list').addEventListener('input', function (e) {
    var box = e.target.closest('.fix');
    if (box && fixOpen[box.getAttribute('data-box')]) fixOpen[box.getAttribute('data-box')].text = e.target.value;
  });
  $('list').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var id;
    if ((id = b.getAttribute('data-fix'))) {
      if (fixOpen[id]) delete fixOpen[id]; else fixOpen[id] = { text: '' };
      render(last);
      var t = document.querySelector('[data-box="' + id + '"] textarea');
      if (t) t.focus();
    } else if ((id = b.getAttribute('data-cancel'))) {
      delete fixOpen[id]; render(last);
    } else if ((id = b.getAttribute('data-send'))) {
      var box = fixOpen[id];
      if (!box || !box.text.trim()) { fixOpen[id] = { text: box ? box.text : '', msg: 'כותבים מה לתקן.', bad: true }; render(last); return; }
      b.disabled = true;
      api('POST', 'revise', { id: +id, note: box.text }).then(function (r) {
        if (r.ok) { delete fixOpen[id]; say($('msg'), r.message, true); render(r.state); }
        else { fixOpen[id].msg = r.message; fixOpen[id].bad = true; render(last); }
      }).catch(function (err) { fixOpen[id].msg = 'משהו השתבש: ' + err.message; fixOpen[id].bad = true; render(last); });
    }
  });

  // ---------- settings ----------
  function showSettings(show) {
    $('home').hidden = show; $('settingsView').hidden = !show;
    $('tab').querySelector('span').textContent = show ? 'חזרה' : 'הגדרות';
    say($('setMsg'), ''); say($('keyMsg2'), '');
    if (show) loadSettings();
    window.scrollTo(0, 0);
  }
  function loadSettings() { api('GET', 'settings').then(fillSettings).catch(function (e) { say($('setMsg'), e.message); }); }
  function fillSettings(r) {
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      var k = el.getAttribute('data-key'), v = r.values[k] || '';
      if (el.classList.contains('seg')) el.querySelectorAll('button').forEach(function (b) { b.classList.toggle('sel', b.getAttribute('data-v') === v); });
      else { el.value = v; if (/^field_/.test(k)) el.placeholder = r.detected[k.slice(6)] ? 'זוהה: ' + r.detected[k.slice(6)] : 'לא זוהה'; }
    });
    $('keyState').textContent = r.hasKey ? 'שמור מפתח שמסתיים ב-' + r.keyEnd : 'עוד לא נשמר מפתח.';
    $('siteInfo').textContent = 'בחנות: ' + r.categories + ' קטגוריות' + (r.brandTaxonomy ? ', מותגים (' + r.brandTaxonomy + ')' : ', בלי מותגים');
  }
  document.querySelectorAll('#nps-app .seg button').forEach(function (b) {
    b.addEventListener('click', function () { b.parentNode.querySelectorAll('button').forEach(function (x) { x.classList.toggle('sel', x === b); }); });
  });
  function collect() {
    var out = {};
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      if (el.classList.contains('seg')) { var s = el.querySelector('.sel'); if (s) out[el.getAttribute('data-key')] = s.getAttribute('data-v'); }
      else out[el.getAttribute('data-key')] = el.value;
    });
    return out;
  }
  if (!NPS.canSettings) $('tab').hidden = true;
  $('tab').addEventListener('click', function () { showSettings($('settingsView').hidden); });
  $('back').addEventListener('click', function () { showSettings(false); });
  $('saveSettings').addEventListener('click', function () {
    $('saveSettings').disabled = true;
    api('POST', 'settings', { values: collect() }).then(function (r) {
      $('saveSettings').disabled = false; fillSettings(r); say($('setMsg'), 'ההגדרות נשמרו ✓ הן ישמשו מהסריקה הבאה.', true);
    }).catch(function (e) { $('saveSettings').disabled = false; say($('setMsg'), 'משהו השתבש: ' + e.message); });
  });
  $('reset').addEventListener('click', function () {
    api('POST', 'settings/reset').then(function (r) { fillSettings(r); say($('setMsg'), 'חזרנו להגדרות ברירת המחדל ✓', true); });
  });

  refresh();
})();
