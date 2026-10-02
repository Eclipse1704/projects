<?php
// Tests: a real WordPress (SQLite) + WooCommerce stand-in, fake Claude, fake manufacturer sites.
// Run: NPS_WP_DIR=/path/to/wordpress php tests/run.php   (FAST=0 = batch mode)
require __DIR__ . '/bootstrap.php';

$FAST = getenv('FAST') !== '0';
$results = [];
function test($name, $fn) {
    global $results;
    reset_site();
    try { $fn(); $results[] = ['✓', $name]; }
    catch (Throwable $e) { $results[] = ['✗', $name, $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine()]; }
}
function ok($cond, $msg = 'expected true') { if (!$cond) throw new Exception($msg); }
function eq($a, $b, $msg = '') { if ($a !== $b) throw new Exception(($msg ? $msg . ': ' : '') . 'expected ' . var_export($b, true) . ' got ' . var_export($a, true)); }
function has($s, $needle, $msg = '') { if (strpos((string) $s, $needle) === false) throw new Exception(($msg ? $msg . ': ' : '') . "missing '$needle' in: " . mb_substr((string) $s, 0, 300)); }

// ---------- fake web ----------

function jpeg($w, $h, $seed) {
    $im = imagecreatetruecolor($w, $h);
    mt_srand($seed);
    for ($i = 0; $i < 400; $i++) imagefilledrectangle($im, mt_rand(0, $w), mt_rand(0, $h), mt_rand(0, $w), mt_rand(0, $h), mt_rand(0, 0xffffff));
    ob_start(); imagejpeg($im, null, 90); return ob_get_clean();
}
$GLOBALS['IMG'] = ['a1' => jpeg(1200, 900, 1), 'a2' => jpeg(1200, 900, 2), 'a3' => jpeg(1200, 900, 3), 'small' => jpeg(400, 300, 4)];
$GLOBALS['PDF'] = "%PDF-1.4\n" . str_repeat('0', 3000) . "\n%%EOF";
$GLOBALS['WEB'] = [];
function page($body) { return ['code' => 200, 'body' => "<!doctype html><html><body>$body</body></html>", 'headers' => ['content-type' => 'text/html; charset=utf-8']]; }
function base_web() {
    return [
        'https://maker.test/p/a100' => page('<main><h1>A100 Videoscope</h1><p>' . str_repeat('Good product. ', 40) . '</p>
            <img src="/i/a1-300x225.jpg" srcset="/i/a1-300x225.jpg 300w, /i/a1.jpg 1200w"><img src="/i/a2.jpg"><img src="/i/a3.jpg"><img src="/i/logo.png">
            <a href="/d/A100-brochure.pdf">Brochure</a> <a href="/d/A100-user-manual.pdf">User manual</a>
            <iframe src="https://www.youtube.com/embed/AbCdEfGhIjK" title="A100 demo"></iframe></main>'),
        'https://maker.test/i/a1.jpg' => ['code' => 200, 'body' => $GLOBALS['IMG']['a1'], 'headers' => ['content-type' => 'image/jpeg']],
        'https://maker.test/i/a1-300x225.jpg' => ['code' => 200, 'body' => $GLOBALS['IMG']['small'], 'headers' => ['content-type' => 'image/jpeg']],
        'https://maker.test/i/a2.jpg' => ['code' => 200, 'body' => $GLOBALS['IMG']['a2'], 'headers' => ['content-type' => 'image/jpeg']],
        'https://maker.test/i/a3.jpg' => ['code' => 200, 'body' => $GLOBALS['IMG']['a3'], 'headers' => ['content-type' => 'application/octet-stream']],
        'https://maker.test/d/A100-brochure.pdf' => ['code' => 200, 'body' => $GLOBALS['PDF'], 'headers' => ['content-type' => 'application/pdf']],
        'https://maker.test/d/A100-user-manual.pdf' => ['code' => 200, 'body' => $GLOBALS['PDF'] . 'manual', 'headers' => ['content-type' => 'application/pdf']],
    ];
}
function web_answer($url, $method, $body, $headers) {
    if (strpos($url, 'https://api.test/') === 0) return $GLOBALS['CLAUDE']->handle($url, $method, $body, $headers);
    $GLOBALS['FETCHES'][] = $url;
    return $GLOBALS['WEB'][$url] ?? null;
}
add_filter('pre_http_request', function ($pre, $args, $url) {
    $r = web_answer($url, $args['method'], $args['body'] ?? null, $args['headers'] ?? []);
    if (!empty($r['timeout'])) return new WP_Error('http_request_failed', 'cURL error 28: Operation timed out');
    if (!$r) $r = ['code' => 404, 'body' => 'not found', 'headers' => []];
    return ['headers' => $r['headers'] ?? [], 'body' => is_string($r['body']) ? $r['body'] : wp_json_encode($r['body']), 'response' => ['code' => $r['code'] ?? 200, 'message' => ''], 'cookies' => [], 'filename' => null];
}, 10, 3);
add_filter('nps_http_multi', function ($pre, $reqs) {
    $GLOBALS['MULTI'][] = count($reqs);
    $out = [];
    foreach ($reqs as $i => $q) {
        $r = web_answer($q['url'], $q['method'] ?? 'GET', $q['body'] ?? null, $q['headers'] ?? []);
        if (!empty($r['timeout'])) { $out[$i] = ['code' => 0, 'body' => '', 'headers' => [], 'error' => 'timed out']; continue; }
        if (!$r) $r = ['code' => 404, 'body' => 'not found', 'headers' => []];
        if (empty($q['redirect']) && isset($q['redirect']) && false) {}
        $out[$i] = ['code' => $r['code'] ?? 200, 'body' => is_string($r['body']) ? $r['body'] : wp_json_encode($r['body']), 'headers' => $r['headers'] ?? [], 'error' => ''];
    }
    return $out;
}, 10, 2);

// ---------- fake Claude (direct calls + batches) ----------

class FakeClaude {
    public $answer; public $key = 'sk-ant-test'; public $batches = []; public $requests = []; public $direct = 0; public $cancelled = [];
    public $polls_until_ended = 1;
    function __construct($answer) { $this->answer = $answer; }
    function handle($url, $method, $body, $headers) {
        $json = function ($b, $code = 200) { return ['code' => $code, 'body' => wp_json_encode($b), 'headers' => ['content-type' => 'application/json']]; };
        if (($headers['x-api-key'] ?? '') !== $this->key) return $json(['type' => 'error', 'error' => ['type' => 'authentication_error', 'message' => 'invalid x-api-key']], 401);
        $path = parse_url($url, PHP_URL_PATH);
        $usage = ['input_tokens' => 100000, 'output_tokens' => 5000, 'server_tool_use' => ['web_search_requests' => 2]];
        if ($path === '/v1/models') return $json(['data' => []]);
        if ($path === '/v1/messages' && $method === 'POST') {
            $params = json_decode($body, true);
            $this->requests[] = $params; $this->direct++;
            $a = ($this->answer)($params);
            if (!empty($a['timeout'])) return ['timeout' => true];
            if (!empty($a['status'])) return $json(['type' => 'error', 'error' => ['message' => 'busy']], $a['status']);
            return $json(['type' => 'message', 'role' => 'assistant', 'content' => $a['content'], 'stop_reason' => $a['stop_reason'] ?? 'end_turn', 'usage' => $usage]);
        }
        if ($path === '/v1/messages/batches' && $method === 'POST') {
            $b = json_decode($body, true);
            $id = 'msgbatch_' . (count($this->batches) + 1);
            $this->batches[$id] = ['reqs' => $b['requests'], 'polls' => 0];
            foreach ($b['requests'] as $r) $this->requests[] = $r['params'];
            return $json(['id' => $id, 'processing_status' => 'in_progress']);
        }
        if (preg_match('#^/v1/messages/batches/(\w+)/cancel$#', $path, $m)) { $this->cancelled[] = $m[1]; return $json(['id' => $m[1]]); }
        if (preg_match('#^/v1/messages/batches/(\w+)$#', $path, $m)) {
            if (!isset($this->batches[$m[1]])) return $json(['error' => ['message' => 'not found']], 404);
            $this->batches[$m[1]]['polls']++;
            return $json(['id' => $m[1], 'processing_status' => $this->batches[$m[1]]['polls'] > $this->polls_until_ended ? 'ended' : 'in_progress', 'results_url' => 'https://api.test/results/' . $m[1]]);
        }
        if (preg_match('#^/results/(\w+)$#', $path, $m)) {
            $lines = [];
            foreach ($this->batches[$m[1]]['reqs'] as $r) {
                $a = ($this->answer)($r['params']);
                $res = !empty($a['error']) || !empty($a['status']) || !empty($a['timeout']) ? ['type' => 'errored', 'error' => ['error' => ['message' => $a['error'] ?? 'busy']]]
                    : ['type' => 'succeeded', 'message' => ['content' => $a['content'], 'stop_reason' => $a['stop_reason'] ?? 'end_turn', 'usage' => $usage]];
                $lines[] = wp_json_encode(['custom_id' => $r['custom_id'], 'result' => $res]);
            }
            return ['code' => 200, 'body' => implode("\n", $lines), 'headers' => []];
        }
        return null;
    }
}
function text_answer($t) { return ['content' => [['type' => 'text', 'text' => $t]]]; }
$OFFICIAL = ['manufacturer' => 'Maker', 'model' => 'A100', 'official_domains' => ['maker.test'], 'official_product_url' => 'https://maker.test/p/a100', 'official_downloads_url' => '', 'site_is_manufacturer' => true];
function research_answer() { global $OFFICIAL; return text_answer("Found it.\n```json\n" . wp_json_encode($OFFICIAL) . "\n```"); }
function hebrew($extra = []) {
    return text_answer(wp_json_encode(array_merge([
        'name' => 'וידאוסקופ תעשייתי Maker A100', 'short_description' => 'וידאוסקופ קטן לבדיקה חזותית של מנועים וצנרת.',
        'description_paragraphs' => ['פסקה ראשונה על המוצר.', 'פסקה שנייה עם נתונים: IP54.'], 'usage' => ['בדיקת מנועים', 'בדיקת צנרת'],
        'specs' => [['name' => 'הגנה', 'value' => 'IP54']], 'category' => 'וידאוסקופים', 'tags' => ['וידאוסקופ', 'בדיקה חזותית'],
        'focus_keyphrase' => 'וידאוסקופ תעשייתי', 'image_indexes' => [0, 1, 2], 'brochure_index' => 0, 'manual_index' => 1, 'video_indexes' => [0],
    ], $extra), JSON_UNESCAPED_UNICODE));
}
function normal($params) { return !empty($params['tools']) ? research_answer() : hebrew(); }
function last_text($c) { $r = end($c->requests); return end($r['messages'][0]['content'])['text'] ?? ''; }

// ---------- site helpers ----------

function reset_site() {
    global $wpdb, $FAST;
    foreach (get_posts(['post_type' => ['product', 'attachment'], 'post_status' => 'any', 'numberposts' => -1, 'fields' => 'ids']) as $id) wp_delete_post($id, true);
    foreach (['product_cat', 'product_tag', 'product_brand'] as $t) foreach (get_terms(['taxonomy' => $t, 'hide_empty' => false, 'fields' => 'ids']) as $tid) wp_delete_term($tid, $t);
    $wpdb->query('DELETE FROM ' . nps_table());
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'nps\\_%' OR option_name LIKE '\\_transient\\_nps\\_%' OR option_name LIKE '\\_transient\\_timeout\\_nps\\_%'");
    wp_cache_flush();
    nps_forget_settings();
    $GLOBALS['as_queue'] = []; $GLOBALS['FETCHES'] = []; $GLOBALS['MULTI'] = []; $GLOBALS['MAILS'] = [];
    $GLOBALS['WEB'] = base_web();
    $GLOBALS['CLAUDE'] = new FakeClaude('normal');
    update_option('nps_api_key', 'sk-ant-test');
    nps_save_settings(['fast' => $FAST ? 'yes' : 'no']);
    foreach (['וידאוסקופים', 'מצלמות תרמיות'] as $c) wp_insert_term($c, 'product_cat');
    wp_set_current_user(1);
}
add_filter('pre_wp_mail', function ($null, $atts) { $GLOBALS['MAILS'][] = $atts; return true; }, 10, 2);

// An older product made by hand, with the theme's ACF-like fields.
function seed_existing_product() {
    $id = wp_insert_post(['post_type' => 'product', 'post_status' => 'publish', 'post_title' => 'מוצר קיים', 'post_content' => str_repeat('תוכן של מוצר קיים בחנות. ', 60)]);
    update_post_meta($id, 'catalog_pdf', 'https://shop.test/wp-content/uploads/x.pdf');
    update_post_meta($id, '_catalog_pdf', 'field_abc1');
    update_post_meta($id, 'user_manual', 'https://shop.test/wp-content/uploads/m.pdf');
    update_post_meta($id, '_user_manual', 'field_abc2');
    update_post_meta($id, 'product_video', 'https://www.youtube.com/watch?v=zzzzzzzzzzz');
    return $id;
}

function run_ticks($max = 60) {
    for ($i = 0; $i < $max && $GLOBALS['as_queue']; $i++) {
        array_shift($GLOBALS['as_queue']);
        nps_forget_settings();
        $user = get_current_user_id();
        wp_set_current_user(0);   // background jobs run without a logged-in user
        do_action('nps_tick');
        wp_set_current_user($user);
    }
    return $i;
}
function rest($method, $path, $params = []) {
    $req = new WP_REST_Request($method, '/nps/v1/' . $path);
    foreach ($params as $k => $v) $req->set_param($k, $v);
    $r = rest_do_request($req);
    return ['status' => $r->get_status(), 'data' => json_decode(wp_json_encode($r->get_data()), true)];
}
function start($links) { return rest('POST', 'start', ['text' => implode("\n", (array) $links)])['data']; }
function items() { return rest('GET', 'state')['data']['items']; }
function finished($it) { return in_array($it['state'], ['done', 'warn'], true); }
function products() { return get_posts(['post_type' => 'product', 'post_status' => 'any', 'numberposts' => -1, 'meta_key' => '_nps_source_link']); }
function attachments_named($product) {
    $ids = array_filter(array_merge([(int) get_post_meta($product, '_thumbnail_id', true)], array_map('intval', explode(',', (string) get_post_meta($product, '_product_image_gallery', true)))));
    return array_map(function ($id) { return basename(get_attached_file($id)); }, array_values($ids));
}

require __DIR__ . '/cases.php';

foreach ($results as $r) echo implode('  ', $r), "\n";
$failed = count(array_filter($results, function ($r) { return $r[0] === '✗'; }));
echo "\n" . (count($results) - $failed) . '/' . count($results) . " passed" . ($FAST ? '' : ' (batch mode)') . "\n";
exit($failed ? 1 : 0);
