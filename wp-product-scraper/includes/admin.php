<?php
// The screen: Products -> סורק מוצרים. Paste links, press start, watch progress, open the drafts, fix texts, settings.

if (!defined('ABSPATH')) exit;

add_action('admin_menu', function () {
    $hook = add_submenu_page('edit.php?post_type=product', 'סורק מוצרים', 'סורק מוצרים', 'edit_products', 'nps-scraper', 'nps_render_page');
    add_action('load-' . $hook, function () {
        add_action('admin_enqueue_scripts', function () {
            wp_enqueue_style('nps-font', 'https://fonts.googleapis.com/css2?family=Heebo:wght@400;500;700;800&display=swap', [], null);
            wp_enqueue_style('nps-admin', plugins_url('assets/admin.css', NPS_FILE), [], NPS_VERSION);
            wp_enqueue_script('nps-admin', plugins_url('assets/admin.js', NPS_FILE), [], NPS_VERSION, true);
            wp_localize_script('nps-admin', 'NPS', ['root' => esc_url_raw(rest_url('nps/v1/')), 'nonce' => wp_create_nonce('wp_rest'), 'canSettings' => current_user_can('manage_woocommerce')]);
        });
    });
});

add_filter('plugin_action_links_' . plugin_basename(NPS_FILE), function ($links) {
    array_unshift($links, '<a href="' . esc_url(admin_url('edit.php?post_type=product&page=nps-scraper')) . '">פתיחה</a>');
    return $links;
});

add_action('admin_notices', function () {
    if (!class_exists('WooCommerce') && current_user_can('activate_plugins')) {
        echo '<div class="notice notice-error"><p>סורק מוצרים צריך את WooCommerce פעיל.</p></div>';
    }
});

function nps_render_page() {
    include NPS_DIR . 'assets/page.php';
}

// ---------- REST API for the screen ----------

add_action('rest_api_init', function () {
    $can = function () { return current_user_can('edit_products'); };
    $admin = function () { return current_user_can('manage_woocommerce'); };
    $routes = [
        ['state', 'GET', 'nps_api_state', $can],
        ['start', 'POST', 'nps_api_start', $can],
        ['revise', 'POST', 'nps_api_revise', $can],
        ['stop', 'POST', 'nps_api_stop', $can],
        ['clear', 'POST', 'nps_api_clear', $can],
        ['export', 'GET', 'nps_api_export', $can],
        ['settings', 'GET', 'nps_api_get_settings', $admin],
        ['settings', 'POST', 'nps_api_save_settings', $admin],
        ['settings/reset', 'POST', 'nps_api_reset_settings', $admin],
        ['key', 'POST', 'nps_api_save_key', $admin],
    ];
    foreach ($routes as $r) register_rest_route('nps/v1', '/' . $r[0], ['methods' => $r[1], 'callback' => $r[2], 'permission_callback' => $r[3]]);
});

function nps_steps() {
    return [
        'queued' => ['ממתין להתחלה', 5, 'working'],
        'research' => ['מחפש את היצרן והאתר הרשמי', 25, 'working'],
        'official' => ['קורא את אתר היצרן', 45, 'working'],
        'write' => ['כותב בעברית', 65, 'working'],
        'save' => ['מכניס לחנות: תמונות, קבצים ושדות', 85, 'working'],
        'done' => ['מוכן בחנות כטיוטה', 100, 'done'],
        'done_notes' => ['מוכן כטיוטה, חסר משהו', 100, 'warn'],
        'error' => ['נכשל', 100, 'error'],
        'stopped' => ['נעצר', 0, 'stopped'],
    ];
}

function nps_api_state() {
    nps_keep_alive();
    $steps = nps_steps();
    $items = [];
    foreach (nps_list_items(60) as $p) {
        $st = $steps[$p['status']] ?? ['', 0, 'idle'];
        if (in_array($p['stage'], ['research_wait', 'write_wait'], true)) $st[0] .= ' (ממתין לתשובה מ-Claude)';
        $pid = $p['product_id'];
        $exists = $pid && get_post_status($pid) && get_post_status($pid) !== 'trash';
        $items[] = [
            'id' => $p['id'], 'link' => $p['link'], 'name' => $p['row']['name'], 'manufacturer' => $p['row']['manufacturer'],
            'step' => $st[0], 'pct' => $st[1], 'state' => $st[2], 'notes' => $p['row']['notes'], 'cost' => $p['cost'] ? number_format($p['cost'], 2) : '',
            'editUrl' => $exists && in_array($p['stage'], ['done', 'error', 'stopped'], true) ? admin_url('post.php?post=' . $pid . '&action=edit') : '',
            'viewUrl' => $exists ? get_preview_post_link($pid) : '',
            'canFix' => !empty($p['content']) && $exists && !in_array($p['stage'], NPS_ACTIVE_STAGES, true),
        ];
    }
    $run = nps_get('run', []);
    return [
        'hasKey' => (bool) nps_settings()['api_key'],
        'items' => $items,
        'runCost' => number_format((float) ($run['cost'] ?? 0), 2),
        'draftsUrl' => admin_url('edit.php?post_type=product&post_status=draft'),
        'worker' => ['running' => nps_active_count() > 0, 'lastError' => (string) nps_get('last_error', '')],
    ];
}

function nps_api_start(WP_REST_Request $req) {
    if (!nps_settings()['api_key']) return ['ok' => false, 'needKey' => true, 'message' => 'קודם מדביקים את מפתח ה-API למעלה.'];
    preg_match_all('#https?://[^\s"\'<>]+#i', (string) $req->get_param('text'), $m);
    $links = [];
    foreach ($m[0] as $l) { $l = rtrim($l, '),.;:!?'); if (!in_array($l, $links, true)) $links[] = $l; }
    if (!$links) return ['ok' => false, 'message' => 'לא מצאתי קישורים. מדביקים קישורים שמתחילים ב-https://'];
    $n = nps_queue_links($links);
    return ['ok' => true, 'message' => ($n === 1 ? 'מוצר אחד התחיל.' : $n . ' מוצרים התחילו.') . ' אפשר לסגור את הדף - העבודה ממשיכה ברקע.'];
}

function nps_api_revise(WP_REST_Request $req) {
    $note = trim((string) $req->get_param('note'));
    if ($note === '') return ['ok' => false, 'message' => 'כותבים מה לתקן.'];
    if (!nps_settings()['api_key']) return ['ok' => false, 'message' => 'חסר מפתח API.'];
    $err = nps_revise((int) $req->get_param('id'), mb_substr($note, 0, 2000));
    return $err ? ['ok' => false, 'message' => $err] : ['ok' => true, 'message' => 'Claude מתקן את הטקסט. זה לוקח כמה דקות.', 'state' => nps_api_state()];
}

function nps_api_stop() {
    nps_stop_all();
    return nps_api_state();
}

// Removes finished products from the list (the products in the shop stay).
function nps_api_clear() {
    global $wpdb;
    $in = "'" . implode("','", NPS_ACTIVE_STAGES) . "'";
    $wpdb->query('DELETE FROM ' . nps_table() . " WHERE stage NOT IN ($in)");
    return nps_api_state();
}

function nps_api_export() {
    $steps = nps_steps();
    $rows = [['שם מוצר', 'יצרן', 'מצב', 'עריכה בחנות', 'קישור מקור', 'הערות', 'עלות ($)']];
    foreach (array_reverse(nps_list_items(1000)) as $p) {
        $rows[] = [$p['row']['name'], $p['row']['manufacturer'], $steps[$p['status']][0] ?? $p['status'],
            $p['product_id'] ? admin_url('post.php?post=' . $p['product_id'] . '&action=edit') : '', $p['link'], $p['row']['notes'], number_format($p['cost'], 2)];
    }
    $out = "\xEF\xBB\xBF";
    foreach ($rows as $r) {
        $out .= implode(',', array_map(function ($v) {
            $v = (string) $v;
            if (preg_match('/^[=+@]|^-[^\d.]/u', $v)) $v = "'" . $v;
            return preg_match('/[",\n]/', $v) ? '"' . str_replace('"', '""', $v) . '"' : $v;
        }, $r)) . "\r\n";
    }
    return ['csv' => $out];
}

function nps_api_get_settings() {
    $s = nps_settings();
    $values = [];
    foreach (nps_default_settings() as $k => $v) $values[$k] = is_bool($s[$k]) ? ($s[$k] ? 'yes' : 'no') : $s[$k];
    $found = get_transient('nps_detected_fields');
    if (!is_array($found)) { $found = nps_detect_fields(); set_transient('nps_detected_fields', $found, DAY_IN_SECONDS); }
    return ['values' => $values, 'hasKey' => (bool) $s['api_key'], 'keyEnd' => $s['api_key'] ? substr($s['api_key'], -4) : '', 'detected' => $found,
        'categories' => count(nps_site_categories()), 'brandTaxonomy' => nps_brand_taxonomy()];
}

function nps_api_save_settings(WP_REST_Request $req) {
    nps_save_settings((array) $req->get_param('values'));
    delete_transient('nps_detected_fields');
    return nps_api_get_settings();
}

function nps_api_reset_settings() {
    delete_option('nps_settings');
    return nps_api_get_settings();
}

function nps_api_save_key(WP_REST_Request $req) {
    $key = trim((string) $req->get_param('key'));
    if (strpos($key, 'sk-ant-') !== 0) return ['ok' => false, 'message' => 'המפתח מתחיל ב-sk-ant-. מעתיקים אותו שוב מ-console.anthropic.com'];
    $s = nps_settings();
    $r = nps_http('GET', $s['api_base'] . '/v1/models', ['headers' => ['x-api-key' => $key, 'anthropic-version' => '2023-06-01'], 'trusted' => true]);
    if ($r['code'] === 401 || $r['code'] === 403) return ['ok' => false, 'message' => 'המפתח לא תקין. מעתיקים אותו שוב מ-console.anthropic.com'];
    update_option('nps_api_key', $key, false);
    return ['ok' => true, 'message' => 'המפתח נשמר ✓'];
}
