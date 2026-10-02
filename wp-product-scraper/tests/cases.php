<?php
// The test scenarios (loaded by run.php).

test('a link becomes a draft product with all its fields, images, catalog, manual and video', function () {
    $old = seed_existing_product();
    $r = start('https://maker.test/p/a100');
    ok($r['ok'], $r['message']);
    run_ticks();
    $ps = products();
    eq(count($ps), 1, 'products');
    $p = $ps[0];
    eq($p->post_status, 'draft');
    eq($p->post_title, 'וידאוסקופ תעשייתי Maker A100');
    eq($p->post_content, "<p>פסקה ראשונה על המוצר.</p>\n<p>פסקה שנייה עם נתונים: IP54.</p>\n<ul>\n<li>בדיקת מנועים</li>\n<li>בדיקת צנרת</li>\n</ul>");
    eq($p->post_excerpt, '<p>וידאוסקופ קטן לבדיקה חזותית של מנועים וצנרת.</p>');
    eq(wp_get_object_terms($p->ID, 'product_cat', ['fields' => 'names']), ['וידאוסקופים']);
    eq(wp_get_object_terms($p->ID, 'product_tag', ['fields' => 'names', 'orderby' => 'term_id']), ['וידאוסקופ', 'בדיקה חזותית']);
    eq(wp_get_object_terms($p->ID, 'product_brand', ['fields' => 'names']), ['Maker']);
    eq(get_post_meta($p->ID, '_yoast_wpseo_focuskw', true), 'וידאוסקופ תעשייתי');
    eq(get_post_meta($p->ID, '_nps_source_link', true), 'https://maker.test/p/a100');
    // images: full size (not the 300px thumbnail), named MAKER-A100-00X, main + gallery, alt text
    eq(attachments_named($p->ID), ['MAKER-A100-001.jpg', 'MAKER-A100-002.jpg', 'MAKER-A100-003.jpg']);
    $main = (int) get_post_meta($p->ID, '_thumbnail_id', true);
    eq(md5_file(get_attached_file($main)), md5($GLOBALS['IMG']['a1']), 'main image is the full-size file');
    eq(get_post_meta($main, '_wp_attachment_image_alt', true), 'וידאוסקופ תעשייתי Maker A100');
    // the theme's fields, found from the existing product (with their ACF field reference)
    has(get_post_meta($p->ID, 'catalog_pdf', true), 'MAKER-A100-BROCHURE');
    eq(get_post_meta($p->ID, '_catalog_pdf', true), 'field_abc1');
    has(get_post_meta($p->ID, 'user_manual', true), 'MAKER-A100-MANUAL');
    eq(get_post_meta($p->ID, 'product_video', true), 'https://www.youtube.com/watch?v=AbCdEfGhIjK');
    // the screen
    $it = items()[0];
    eq($it['state'], 'done', $it['step'] . ' ' . $it['notes']);
    eq($it['editUrl'], admin_url('post.php?post=' . $p->ID . '&action=edit'));
    eq($it['canFix'], true);
    ok(+$it['cost'] > 0, 'cost');
    // the old product is untouched
    eq(get_post_meta($old, 'catalog_pdf', true), 'https://shop.test/wp-content/uploads/x.pdf');
    eq(count($GLOBALS['as_queue']), 0, 'worker still scheduled after everything finished');
    eq((int) $p->post_author, 1, 'author');
});

test('Claude writes in the shop\'s style: categories, glossary and existing products are in the prompt', function () {
    seed_existing_product();
    start('https://maker.test/p/a100');
    run_ticks();
    $write = null;
    foreach ($GLOBALS['CLAUDE']->requests as $r) if (!empty($r['system'])) $write = $r;
    $sys = $write['system'][0]['text'];
    has($sys, "<site_categories>\nוידאוסקופים\nמצלמות תרמיות");
    has($sys, 'videoscope = וידאוסקופ');
    has($sys, 'תוכן של מוצר קיים בחנות', 'style example from the shop');
    eq($write['output_config']['format']['type'], 'json_schema');
    ok(!isset($write['output_config']['format']['schema']['properties']['slug']), 'slug left to WordPress');
    eq($write['messages'][0]['content'][0]['source']['media_type'] ?? '', 'application/pdf', 'brochure sent to Claude');
});

test('a category that is not in the shop is left empty, with a note', function () {
    $GLOBALS['CLAUDE']->answer = function ($p) { return !empty($p['tools']) ? research_answer() : hebrew(['category' => 'קטגוריה שלא קיימת']); };
    start('https://maker.test/p/a100');
    run_ticks();
    $p = products()[0];
    eq(wp_get_object_terms($p->ID, 'product_cat', ['fields' => 'names']), []);
    has(items()[0]['notes'], 'לבחור קטגוריה');
});

test('"fix the text" updates the same product: no duplicate, no images uploaded again', function () {
    $GLOBALS['CLAUDE']->answer = function ($p) {
        if (!empty($p['tools'])) return research_answer();
        $t = end($p['messages'][0]['content'])['text'];
        return hebrew(strpos($t, '<requested_changes>') !== false ? ['name' => 'שם מתוקן A100'] : []);
    };
    start('https://maker.test/p/a100');
    run_ticks();
    $atts = count(get_posts(['post_type' => 'attachment', 'numberposts' => -1, 'post_status' => 'any']));
    $it = items()[0];
    eq(rest('POST', 'revise', ['id' => $it['id'], 'note' => ''])['data']['ok'], false);
    $r = rest('POST', 'revise', ['id' => $it['id'], 'note' => 'לקצר את התיאור הקצר'])['data'];
    ok($r['ok'], $r['message']);
    eq(rest('POST', 'revise', ['id' => $it['id'], 'note' => 'עוד'])['data']['ok'], false, 'fix accepted while still working');
    run_ticks();
    $t = last_text($GLOBALS['CLAUDE']);
    has($t, "<requested_changes>\nלקצר את התיאור הקצר");
    has($t, 'וידאוסקופ תעשייתי Maker A100', 'previous version sent');
    $ps = products();
    eq(count($ps), 1);
    eq($ps[0]->post_title, 'שם מתוקן A100');
    eq(count(get_posts(['post_type' => 'attachment', 'numberposts' => -1, 'post_status' => 'any'])), $atts, 'files uploaded again');
    eq(count(items()), 1, 'fix added a row');
});

test('the same link scanned again updates its product; if it was deleted, a new draft is made', function () {
    start('https://maker.test/p/a100');
    run_ticks();
    start('https://maker.test/p/a100');
    run_ticks();
    eq(count(products()), 1);
    wp_trash_post(products()[0]->ID);
    start('https://maker.test/p/a100');
    run_ticks();
    eq(count(get_posts(['post_type' => 'product', 'post_status' => 'draft', 'meta_key' => '_nps_source_link'])), 1);
});

test('words from "avoid words" send the text back to Claude with the problem', function () {
    $n = 0;
    $GLOBALS['CLAUDE']->answer = function ($p) use (&$n) {
        if (!empty($p['tools'])) return research_answer();
        $n++;
        return hebrew(['description_paragraphs' => [$n === 1 ? 'המכשיר הינו פתרון מושלם לבדיקה.' : 'המכשיר מתאים לבדיקה.']]);
    };
    start('https://maker.test/p/a100');
    run_ticks();
    eq($n, 2);
    has(last_text($GLOBALS['CLAUDE']), 'avoid_words');
    has(products()[0]->post_content, 'המכשיר מתאים לבדיקה');
    ok(nps_contains_word('המכשיר הינו טוב', 'הינו') && !nps_contains_word('בהינותו', 'הינו'), 'Hebrew word match');
});

test('wrong API key: the product shows the error and the worker stops', function () {
    update_option('nps_api_key', 'sk-ant-wrong');
    start('https://maker.test/p/a100');
    $ticks = run_ticks(30);
    ok($ticks < 30, 'endless ticks');
    $it = items()[0];
    eq($it['state'], 'error');
    has($it['notes'], 'מפתח ה-API לא תקין');
});

test('a direct call that times out continues as a batch job', function () {
    if (!$GLOBALS['FAST']) return;
    $GLOBALS['CLAUDE']->answer = function ($p) { return empty($p['tools']) && !isset($GLOBALS['in_batch']) ? ['timeout' => true] : normal($p); };
    start('https://maker.test/p/a100');
    $GLOBALS['CLAUDE']->answer = function ($p) { static $direct = 0; if (empty($p['tools'])) { $direct++; if ($direct === 1) return ['timeout' => true]; } return normal($p); };
    run_ticks();
    eq(count($GLOBALS['CLAUDE']->batches), 1, 'batch');
    ok(finished(items()[0]), 'not finished: ' . items()[0]['step']);
});

test('a host that kills long requests: after two cut-off direct calls the product goes to a batch', function () {
    if (!$GLOBALS['FAST']) return;
    start('https://maker.test/p/a100');
    $p = nps_item(items()[0]['id']);
    $p['stage'] = 'research_pending';
    $p['direct_tries'] = ['research' => 2];   // two tries that never came back
    nps_save_item($p);
    run_ticks();
    eq(count($GLOBALS['CLAUDE']->batches), 1);
    ok(finished(items()[0]), 'not finished: ' . items()[0]['step']);
});

test('Claude busy (529): retried, then sent as a batch', function () {
    if (!$GLOBALS['FAST']) return;
    $busy = 0;
    $GLOBALS['CLAUDE']->answer = function ($p) use (&$busy) { if (!empty($p['tools']) && $busy < 3) { $busy++; return ['status' => 529]; } return normal($p); };
    start('https://maker.test/p/a100');
    run_ticks();
    eq($busy, 3);
    ok(finished(items()[0]), 'not finished: ' . items()[0]['step']);
});

test('stop: cancels batch jobs, stops the products and the worker', function () {
    nps_save_settings(['fast' => 'no']);
    $GLOBALS['CLAUDE']->polls_until_ended = 1000;
    start(['https://maker.test/p/a100', 'https://maker.test/p/a100?n=2']);
    run_ticks(3);
    ok($GLOBALS['CLAUDE']->batches, 'no batch');
    $st = rest('POST', 'stop')['data'];
    eq(array_column($st['items'], 'state'), ['stopped', 'stopped']);
    eq(count($GLOBALS['CLAUDE']->cancelled), count($GLOBALS['CLAUDE']->batches));
    eq($GLOBALS['as_queue'], []);
});

test('12 products at once: Claude called several at the same time, all finish', function () {
    $links = [];
    for ($i = 0; $i < 12; $i++) $links[] = 'https://maker.test/p/a100?n=' . $i;
    start($links);
    run_ticks();
    eq(count(array_filter(items(), 'finished')), 12);
    if ($GLOBALS['FAST']) ok(max($GLOBALS['MULTI']) >= 5, 'no parallel calls');
    eq(count(products()), 12);
});

test('screen: permissions, key check, messy text with links, clear, CSV export', function () {
    $sub = wp_insert_user(['user_login' => 'sub', 'user_pass' => 'x', 'role' => 'subscriber']);
    wp_set_current_user($sub);
    eq(rest('POST', 'start', ['text' => 'https://maker.test/p/a100'])['status'], 403);
    $mgr = wp_insert_user(['user_login' => 'mgr', 'user_pass' => 'x', 'role' => 'shop_manager']);
    add_role('shop_manager', 'Shop manager', ['read' => true]);
    wp_set_current_user($mgr);
    eq(rest('GET', 'settings')['status'], 403, 'shop manager without manage_woocommerce sees settings');
    wp_set_current_user(1);
    eq(rest('POST', 'key', ['key' => 'hello'])['data']['ok'], false);
    eq(rest('POST', 'key', ['key' => 'sk-ant-nope'])['data']['ok'], false);
    eq(rest('POST', 'key', ['key' => ' sk-ant-test '])['data']['ok'], true);
    $r = start(['תבדוק: https://maker.test/p/a100, וגם https://maker.test/p/a100.', 'בלי']);
    has($r['message'], 'מוצר אחד התחיל');
    eq(start('אין פה קישורים')['ok'], false);
    run_ticks();
    $csv = rest('GET', 'export')['data']['csv'];
    ok(strpos($csv, "\xEF\xBB\xBF") === 0, 'BOM');
    has($csv, 'וידאוסקופ תעשייתי Maker A100');
    eq(rest('POST', 'clear')['data']['items'], []);
    eq(count(products()), 1, 'clear deleted products');
    wp_delete_user($sub); wp_delete_user($mgr);
});

test('settings: saved, used, reset; unchanged defaults are not stored', function () {
    $s = rest('GET', 'settings')['data'];
    eq($s['values']['model'], 'claude-sonnet-5');
    eq($s['categories'], 2);
    eq($s['brandTaxonomy'], 'product_brand');
    $v = $s['values'];
    $v['model'] = 'claude-opus-5';
    $v['glossary'] .= "\r\nleak = נזילה";
    rest('POST', 'settings', ['values' => $v]);
    eq(nps_settings()['model'], 'claude-opus-5');
    ok(str_ends_with(nps_settings()['glossary'], "\nleak = נזילה"), 'glossary');
    ok(!isset(get_option('nps_settings')['avoid_words']), 'unchanged default stored');
    rest('POST', 'settings/reset');
    eq(nps_settings()['model'], 'claude-sonnet-5');
});

test('email when the run is done', function () {
    start('https://maker.test/p/a100');
    run_ticks();
    eq(count($GLOBALS['MAILS']), 1);
    has($GLOBALS['MAILS'][0]['message'], '1 מוצרים מוכנים');
});

test('a site that is down: the product still finishes, with notes, no files from elsewhere', function () {
    foreach (array_keys($GLOBALS['WEB']) as $u) if ($u !== 'https://maker.test/p/a100') unset($GLOBALS['WEB'][$u]);
    start('https://maker.test/p/a100');
    run_ticks();
    $it = items()[0];
    eq($it['state'], 'warn', $it['notes']);
    has($it['notes'], 'נמצאו 0 תמונות');
    has($it['notes'], 'לא נמצא קטלוג');
});

test('page reading: full-size images, srcset, PDFs, YouTube, relative links', function () {
    $html = '<h1>X</h1><img src="/a/b-150x150.jpg" srcset="/a/b-150x150.jpg 150w,/a/b-768x768.jpg 768w"><a href="../c/photo.jpg"><img src="t.jpg"></a>
      <a href="/files/X_User_Manual.pdf">Manual</a><a href="/f/x-datasheet.pdf">Data</a><iframe src="https://www.youtube.com/embed/videoseries?list=1"></iframe>
      <a href="https://youtu.be/AbCdEfGhIjK">v</a><img src="/img/logo.png">';
    $p = nps_parse_page($html, 'https://m.test/p/q/');
    eq(array_column($p['images'], 'url'), ['https://m.test/a/b.jpg', 'https://m.test/p/q/t.jpg', 'https://m.test/p/c/photo.jpg']);
    eq(array_column($p['pdfs'], 'kind'), ['manual', 'brochure']);
    eq(array_column($p['videos'], 'url'), ['https://www.youtube.com/watch?v=AbCdEfGhIjK']);
    eq(nps_largest_from_srcset('a.jpg 300w,b.jpg 1200w,c.jpg 600w'), 'b.jpg');
    eq(nps_largest_from_srcset('a.jpg 1x, b.jpg 2x'), 'b.jpg');
    eq(nps_canonical_image('https://s.test/products/x_600x.jpg?v=1&width=300'), 'https://s.test/products/x.jpg?v=1');
    eq(nps_file_stem('FOTRIC', 'Fotric 348A'), 'FOTRIC-348A');
});

test('one worker at a time (lock), and a stuck lock is taken over', function () {
    ok(nps_lock(), 'lock');
    ok(!nps_lock(), 'second lock');
    nps_unlock();
    global $wpdb;
    $wpdb->query("INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES ('nps_lock', '" . (time() - 3600) . "', 'no')");
    ok(nps_lock(), 'stale lock not taken over');
    nps_unlock();
});
