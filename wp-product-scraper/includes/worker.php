<?php
// The background worker. Each product moves through these stages:
//   new -> research_pending -> (research_wait) -> official -> write_pending -> (write_wait) -> save -> done
// One "tick" (an Action Scheduler job) takes every product as far as it can, then schedules the next tick.
// Claude is called directly (several products at once) or, if the host cuts long requests off, through
// the Message Batches API (half price, results arrive later).

if (!defined('ABSPATH')) exit;

const NPS_TICK_HOOK = 'nps_tick';
const NPS_GROUP = 'nps';
const NPS_NOW_GROUP = 5;            // Claude calls at the same time
const NPS_MAX_STEP_TRIES = 3;
const NPS_MAX_WRITE_ATTEMPTS = 3;
const NPS_MAX_BATCH_REQUESTS = 20;
const NPS_MAX_PDF_FOR_CLAUDE = 10485760;
const NPS_PRICES = ['claude-sonnet-5' => [2, 10], 'claude-opus-5' => [5, 25]];

add_action(NPS_TICK_HOOK, 'nps_tick');

function nps_status_labels() {
    return [
        'queued' => 'ממתין בתור', 'research' => 'Claude מחפש את היצרן והאתר הרשמי…', 'official' => 'קורא את אתר היצרן…',
        'write' => 'Claude כותב בעברית…', 'save' => 'מכניס לחנות…', 'done' => 'מוכן', 'done_notes' => 'מוכן, חסר משהו',
        'error' => 'נכשל', 'stopped' => 'נעצר',
    ];
}

// ---------- scheduling ----------

function nps_has_pending_tick() {
    if (function_exists('as_get_scheduled_actions')) {
        return (bool) as_get_scheduled_actions(['hook' => NPS_TICK_HOOK, 'status' => ActionScheduler_Store::STATUS_PENDING, 'per_page' => 1], 'ids');
    }
    return (bool) wp_next_scheduled(NPS_TICK_HOOK);
}

function nps_schedule_tick($delay = 0) {
    if (nps_has_pending_tick()) return;
    if (function_exists('as_schedule_single_action')) {
        if ($delay) as_schedule_single_action(time() + $delay, NPS_TICK_HOOK, [], NPS_GROUP);
        else as_enqueue_async_action(NPS_TICK_HOOK, [], NPS_GROUP);
        return;
    }
    wp_schedule_single_event(time() + $delay, NPS_TICK_HOOK);
    if (!$delay) spawn_cron();
}

// The screen calls this while it's open: if the background jobs stopped running (some hosts), start them again.
function nps_keep_alive() {
    if (!nps_active_count()) return;
    $last = (int) nps_get('last_tick', 0);
    if ($last < time() - 180 && !nps_lock_held()) nps_schedule_tick();
}

function nps_lock_held() {
    global $wpdb;
    $t = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'nps_lock'");
    return $t !== null && (int) $t > time() - 900;
}

// ---------- the tick ----------

$GLOBALS['nps_started'] = 0;
function nps_elapsed() { return time() - $GLOBALS['nps_started']; }

// Can this host keep a request open long enough for a direct Claude answer (up to ~5 minutes)?
function nps_direct_ok() {
    $lim = (int) ini_get('max_execution_time');
    return apply_filters('nps_direct_ok', $lim === 0 || $lim >= 320);
}

function nps_tick() {
    if (!nps_lock()) return;
    $GLOBALS['nps_started'] = time();
    nps_set('last_tick', time());
    @set_time_limit(330);
    ignore_user_abort(true);
    $run = nps_get('run', []);
    if (!empty($run['user']) && !get_current_user_id()) wp_set_current_user((int) $run['user']);   // products and images get an author
    try {
        nps_work();
        nps_set('last_error', '');
    } catch (Throwable $e) {
        nps_set('last_error', $e->getMessage());
    } finally {
        nps_unlock();
        nps_clear_prefetch();
    }
    if (nps_active_count()) {
        $busy = (bool) nps_items_in(['new', 'research_pending', 'official', 'write_pending', 'save']);
        nps_schedule_tick($busy ? 0 : 60);
    } else {
        nps_finish_run();
    }
}

function nps_work() {
    $s = nps_settings();
    nps_poll_batches($s);
    nps_recover_lost_waits();
    for ($round = 0; $round < 10 && nps_elapsed() < 120; $round++) {
        $moved = nps_run_local('new');
        $moved = nps_run_claude($s, 'research') || $moved;
        $moved = nps_run_local('official') || $moved;
        $moved = nps_run_claude($s, 'write') || $moved;
        $moved = nps_run_local('save') || $moved;
        if (!$moved) break;
    }
    nps_submit_batches($s, 'research');
    nps_submit_batches($s, 'write');
}

function nps_set_status(&$p, $status, $show = []) {
    $p['status'] = $status;
    nps_save_item($p, $show);
}

function nps_fail(&$p, $e) {
    $msg = $e instanceof Throwable ? $e->getMessage() : (string) $e;
    $p['stage'] = 'error';
    $p['warnings'][] = $msg;
    nps_set_status($p, 'error', ['notes' => $msg]);
}

// ---------- local stages: read pages, save the product ----------

function nps_run_local($stage) {
    $items = nps_items_in([$stage]);
    $moved = false;
    foreach (array_chunk($items, $stage === 'save' ? 2 : 8) as $group) {
        if (nps_elapsed() > 150) break;
        nps_prefetch_for($stage, $group);
        foreach ($group as $p) {
            if (nps_elapsed() > 150) break;
            nps_run_step($p);
            $moved = true;
        }
        nps_clear_prefetch();
    }
    return $moved;
}

function nps_prefetch_for($stage, $group) {
    if ($stage === 'new') nps_prefetch(array_map(function ($p) { return $p['link']; }, $group), false);
    if ($stage === 'official') {
        $urls = [];
        foreach ($group as $p) { $urls[] = $p['research']['official_product_url'] ?? ''; $urls[] = $p['research']['official_downloads_url'] ?? ''; }
        nps_prefetch($urls, false);
    }
}

function nps_run_step($p) {
    $p['step_tries'][$p['stage']] = ($p['step_tries'][$p['stage']] ?? 0) + 1;
    if ($p['step_tries'][$p['stage']] > NPS_MAX_STEP_TRIES) {
        nps_fail($p, 'השלב נקטע שוב ושוב (האתר איטי מדי או הקבצים גדולים מדי). אפשר לנסות שוב מאוחר יותר.');
        return;
    }
    nps_save_item($p);   // count the try first: if the host kills this request, the next tick knows
    try {
        if ($p['stage'] === 'new') nps_step_supplier($p);
        elseif ($p['stage'] === 'official') nps_step_official($p);
        elseif ($p['stage'] === 'save') { nps_step_save($p); nps_finish_product($p); }
    } catch (Throwable $e) {
        nps_fail($p, $e);
    }
}

function nps_step_supplier(&$p) {
    $page = nps_fetch_page($p['link']);
    if ($page) {
        $p['supplier'] = ['title' => $page['title'], 'text' => mb_substr($page['text'], 0, 15000), 'links' => array_slice($page['links'], 0, 600)];
    } else {
        $p['supplier'] = null;
        $p['warnings'][] = 'לא הצלחתי לפתוח את הקישור ישירות; Claude קרא אותו בעצמו';
    }
    $p['stage'] = 'research_pending';
    nps_set_status($p, 'research', ['name' => $page ? $page['title'] : '']);
}

// Read the manufacturer's official pages; images / PDFs / YouTube links come from them only.
function nps_step_official(&$p) {
    $r = &$p['research'];
    $domains = $r['official_domains'];
    $linkHost = preg_replace('/^www\./', '', nps_host($p['link']));
    if ($r['site_is_manufacturer'] && !in_array($linkHost, $domains, true)) $domains[] = $linkHost;
    if (!$r['site_is_manufacturer']) $domains = array_values(array_diff($domains, [$linkHost]));
    $r['official_domains'] = $domains;

    $key = preg_replace('/[^a-z0-9]/', '', strtolower($r['model']));
    $urls = [];
    if ($r['site_is_manufacturer']) $urls[] = $p['link'];
    if ($r['official_product_url'] && nps_is_official($r['official_product_url'], $domains)) $urls[] = $r['official_product_url'];
    foreach ($p['supplier']['links'] ?? [] as $l) {
        $parts = explode('/', rtrim(preg_replace('/[?#].*$/', '', $l['url']), '/'));
        $seg = preg_replace('/[^a-z0-9]/', '', strtolower(end($parts)));
        if (strlen($key) >= 3 && nps_is_official($l['url'], $domains) && strpos($seg, $key) !== false && !preg_match('/\.pdf/i', $l['url'])) $urls[] = $l['url'];
    }
    $urls = array_slice(array_values(array_unique($urls)), 0, 3);

    $off = ['pages' => [], 'images' => [], 'pdfs' => [], 'videos' => []];
    $addAll = function (&$list, $items) { foreach ($items as $x) { $dup = false; foreach ($list as $y) if ($y['url'] === $x['url']) $dup = true; if (!$dup) $list[] = $x; } };
    foreach ($urls as $u) {
        $page = nps_fetch_page($u);
        if (!$page) continue;
        $off['pages'][] = ['url' => $u, 'text' => mb_substr($page['text'], 0, 15000)];
        $addAll($off['images'], $page['images']);
        $addAll($off['pdfs'], $page['pdfs']);
        $addAll($off['videos'], $page['videos']);
    }
    if ($r['official_downloads_url'] && nps_is_official($r['official_downloads_url'], $domains) && !in_array($r['official_downloads_url'], $urls, true)) {
        $dl = nps_fetch_page($r['official_downloads_url']);
        if ($dl) {
            $forProduct = strlen($key) >= 3 && strpos(preg_replace('/[^a-z0-9]/', '', strtolower($r['official_downloads_url'])), $key) !== false;
            $pdfs = array_filter($dl['pdfs'], function ($d) use ($forProduct, $key) {
                return $forProduct || (strlen($key) >= 3 && strpos(preg_replace('/[^a-z0-9]/', '', strtolower($d['label'] . $d['url'])), $key) !== false);
            });
            $addAll($off['pdfs'], array_slice(array_values($pdfs), 0, 20));
        }
    }
    $off['images'] = array_slice($off['images'], 0, 40);
    $p['official'] = $off;
    if (!$domains) $p['warnings'][] = 'לא נמצא אתר רשמי של היצרן';
    elseif (!$off['pages']) $p['warnings'][] = 'לא הצלחתי לקרוא את דף המוצר באתר היצרן';
    unset($r);
    $p['stage'] = 'write_pending';
    nps_set_status($p, 'write', ['manufacturer' => $p['research']['manufacturer']]);
}

function nps_finish_product(&$p) {
    $p['stage'] = 'done';
    $p['revision'] = null;
    $p['edit_url'] = admin_url('post.php?post=' . $p['product_id'] . '&action=edit');
    nps_set_status($p, $p['warnings'] ? 'done_notes' : 'done', ['name' => $p['content']['name'], 'manufacturer' => $p['research']['manufacturer'], 'notes' => implode(' · ', $p['warnings'])]);
}

// ---------- Claude stages ----------

function nps_claude_params($s, &$p, $kind) {
    if ($kind === 'research') {
        $params = nps_research_params($s, $p);
        if (!empty($p['research_continuation'])) $params['messages'][] = $p['research_continuation'];
        return $params;
    }
    $brochure = !empty($p['skip_brochure']) ? null : nps_brochure_for_claude($p);
    $p['last_write_had_brochure'] = (bool) $brochure;
    return nps_write_params($s, $p, nps_style_examples($s), array_values(nps_site_categories()), $brochure, $p['write_feedback'] ?? '');
}

function nps_brochure_for_claude($p) {
    foreach ($p['official']['pdfs'] ?? [] as $d) {
        if ($d['kind'] !== 'brochure') continue;
        $r = nps_fetch($d['url'], true, 60);
        if (!$r || strlen($r['body']) > NPS_MAX_PDF_FOR_CLAUDE || strncmp($r['body'], '%PDF-', 5) !== 0) return null;
        return base64_encode($r['body']);
    }
    return null;
}

// Direct calls, NPS_NOW_GROUP at a time. A product whose direct call was cut off twice goes to a batch.
function nps_run_claude($s, $kind) {
    if (!$s['fast'] || !nps_direct_ok() || !$s['api_key']) return false;
    $moved = false;
    while (nps_elapsed() < 30) {
        $group = [];
        foreach (nps_items_in([$kind . '_pending']) as $p) {
            if (($p['direct_tries'][$kind] ?? 0) >= 2 || !empty($p['use_batch'][$kind])) continue;
            $group[] = $p;
            if (count($group) >= NPS_NOW_GROUP) break;
        }
        if (!$group) break;
        $params = [];
        foreach ($group as $i => &$p) {
            try {
                $params[$i] = nps_claude_params($s, $p, $kind);
            } catch (Throwable $e) {
                nps_fail($p, $e);
                continue;
            }
            $p['direct_tries'][$kind] = ($p['direct_tries'][$kind] ?? 0) + 1;
            nps_save_item($p);
        }
        unset($p);
        if (!$params) continue;
        $answers = nps_claude_now($s, array_values($params));
        $j = 0;
        foreach (array_keys($params) as $i) {
            $p = $group[$i];
            $a = $answers[$j++];
            if (!empty($a['timeout'])) { $p['use_batch'][$kind] = true; nps_save_item($p); continue; }
            if (isset($a['status']) && ($a['status'] === 401 || $a['status'] === 403)) { nps_fail($p, $a['message']); continue; }
            if (isset($a['status']) && ($a['status'] === 408 || $a['status'] === 429 || $a['status'] >= 500)) {
                $p['now_errors'] = ($p['now_errors'] ?? 0) + 1;
                if ($p['now_errors'] >= 3) $p['use_batch'][$kind] = true;
                nps_save_item($p);
                continue;
            }
            $p['direct_tries'][$kind] = 0;
            try {
                nps_add_cost($p, $a['result'], false);
                if ($kind === 'research') nps_apply_research($p, $a['result']);
                else nps_apply_write($p, $a['result']);
            } catch (Throwable $e) {
                nps_fail($p, $e);
                continue;
            }
            $moved = true;
        }
    }
    return $moved;
}

function nps_submit_batches($s, $kind) {
    if (!$s['api_key']) return;
    $todo = array_values(array_filter(nps_items_in([$kind . '_pending']), function ($p) use ($s, $kind) {
        return !$s['fast'] || !nps_direct_ok() || !empty($p['use_batch'][$kind]) || ($p['direct_tries'][$kind] ?? 0) >= 2;
    }));
    foreach (array_chunk($todo, NPS_MAX_BATCH_REQUESTS) as $chunk) {
        if (nps_elapsed() > 200) return;
        $reqs = [];
        $members = [];
        foreach ($chunk as $p) {
            try {
                $reqs[] = ['custom_id' => 'i' . $p['id'], 'params' => nps_claude_params($s, $p, $kind)];
                $members[] = $p;
            } catch (Throwable $e) {
                nps_fail($p, $e);
            }
        }
        if (!$reqs) continue;
        try {
            $batch = nps_claude_request($s, 'POST', '/v1/messages/batches', ['requests' => $reqs]);
        } catch (NPS_Http_Error $e) {
            if ($e->status >= 400 && $e->status < 500 && $e->status !== 429) foreach ($members as $p) nps_fail($p, $e);
            return;   // busy: try again on the next tick
        }
        $batches = nps_get('batches', []);
        $batches[] = ['id' => $batch['id'], 'kind' => $kind, 'members' => array_map(function ($p) { return $p['id']; }, $members), 'fails' => 0];
        nps_set('batches', $batches);
        foreach ($members as $p) {
            $p['stage'] = $kind . '_wait';
            $p['batch_id'] = $batch['id'];
            nps_save_item($p);
        }
    }
}

function nps_poll_batches($s) {
    $batches = nps_get('batches', []);
    if (!$batches) return;
    $keep = [];
    foreach ($batches as $b) {
        try {
            $info = nps_claude_request($s, 'GET', '/v1/messages/batches/' . $b['id']);
            if (($info['processing_status'] ?? '') !== 'ended') { $keep[] = $b; continue; }
            $results = nps_batch_results($s, $info);
        } catch (Throwable $e) {
            $status = $e instanceof NPS_Http_Error ? $e->status : 0;
            if ($status === 404) { nps_release_members($b); continue; }
            if ($status === 401 || $status === 403) { foreach ($b['members'] as $id) { $p = nps_item($id); if ($p) nps_fail($p, $e); } continue; }
            $b['fails']++;
            if ($b['fails'] < 10) $keep[] = $b; else nps_release_members($b);
            continue;
        }
        $byId = [];
        foreach ($results as $r) $byId[$r['custom_id']] = $r['result'];
        foreach ($b['members'] as $id) {
            $p = nps_item($id);
            if (!$p || $p['stage'] !== $b['kind'] . '_wait' || ($p['batch_id'] ?? '') !== $b['id']) continue;
            unset($p['batch_id']);
            $res = $byId['i' . $id] ?? null;
            try {
                nps_add_cost($p, $res, true);
                if ($b['kind'] === 'research') nps_apply_research($p, $res);
                else nps_apply_write($p, $res);
            } catch (Throwable $e) {
                nps_fail($p, $e);
            }
        }
    }
    nps_set('batches', $keep);
}

function nps_release_members($b) {
    foreach ($b['members'] as $id) {
        $p = nps_item($id);
        if ($p && $p['stage'] === $b['kind'] . '_wait') { $p['stage'] = $b['kind'] . '_pending'; unset($p['batch_id']); nps_save_item($p); }
    }
}

// A product waiting on a batch that is no longer known (e.g. the run was cut off) goes back to the queue.
function nps_recover_lost_waits() {
    $known = array_map(function ($b) { return $b['id']; }, nps_get('batches', []));
    foreach (nps_items_in(['research_wait', 'write_wait']) as $p) {
        if (!in_array($p['batch_id'] ?? '', $known, true)) {
            $p['stage'] = str_replace('_wait', '_pending', $p['stage']);
            unset($p['batch_id']);
            nps_save_item($p);
        }
    }
}

function nps_result_error($r) {
    if (!$r) return 'no result';
    if ($r['type'] === 'errored') return $r['error']['error']['message'] ?? 'error';
    return $r['type'];
}

function nps_apply_research(&$p, $result) {
    if (!$result || $result['type'] !== 'succeeded') {
        $p['research_attempts']++;
        $p['research_continuation'] = null;
        if ($p['research_attempts'] < 3) { $p['stage'] = 'research_pending'; nps_save_item($p); return; }
        throw new Exception('Claude: ' . nps_result_error($result));
    }
    $msg = $result['message'];
    // The web search hit its step limit: Claude continues where it stopped (all paused turns as one assistant message).
    if (($msg['stop_reason'] ?? '') === 'pause_turn' && ($p['research_pauses'] ?? 0) < 5) {
        $p['research_pauses'] = ($p['research_pauses'] ?? 0) + 1;
        $before = $p['research_continuation']['content'] ?? [];
        $p['research_continuation'] = ['role' => 'assistant', 'content' => array_merge($before, $msg['content'])];
        $p['stage'] = 'research_pending';
        nps_save_item($p);
        return;
    }
    $r = nps_parse_research($msg);
    if (!$r) $p['research_attempts']++;
    if (!$r && $p['research_attempts'] < 3) { $p['research_continuation'] = null; $p['stage'] = 'research_pending'; nps_save_item($p); return; }
    $p['research'] = $r ?: ['manufacturer' => '', 'model' => '', 'official_domains' => [], 'official_product_url' => '', 'official_downloads_url' => '', 'site_is_manufacturer' => false];
    $p['research_continuation'] = null;
    $p['stage'] = 'official';
    nps_set_status($p, 'official', ['manufacturer' => $p['research']['manufacturer']]);
}

function nps_apply_write(&$p, $result) {
    $p['write_attempts']++;
    if ($result && $result['type'] === 'errored' && !empty($p['last_write_had_brochure'])) {
        $p['skip_brochure'] = true;   // most likely the brochure PDF (too many pages, encrypted...): write without it
        $p['write_attempts']--;
        $p['stage'] = 'write_pending';
        nps_save_item($p);
        return;
    }
    if (!$result || $result['type'] !== 'succeeded' || ($result['message']['stop_reason'] ?? '') === 'refusal') {
        if ($p['write_attempts'] < NPS_MAX_WRITE_ATTEMPTS) { $p['stage'] = 'write_pending'; nps_save_item($p); return; }
        throw new Exception('Claude: ' . ($result && $result['type'] === 'succeeded' ? 'refusal' : nps_result_error($result)));
    }
    $content = json_decode(nps_message_text($result['message']), true);
    if (!is_array($content)) {
        if ($p['write_attempts'] < NPS_MAX_WRITE_ATTEMPTS) { $p['stage'] = 'write_pending'; nps_save_item($p); return; }
        throw new Exception('Claude returned invalid JSON');
    }
    $content = nps_tidy_content($content, array_values(nps_site_categories()));
    $problems = nps_validate_content($content, nps_settings()['avoid_list']);
    if ($problems && $p['write_attempts'] < NPS_MAX_WRITE_ATTEMPTS) {
        $p['write_feedback'] = "\n\nבטיוטה הקודמת היו הבעיות הבאות - תקן/י:\n- " . implode("\n- ", $problems) . "\nהטיוטה הקודמת:\n" . wp_json_encode($content, JSON_UNESCAPED_UNICODE);
        $p['stage'] = 'write_pending';
        nps_save_item($p);
        return;
    }
    $fatal = array_filter($problems, function ($x) { return preg_match('/^missing|not in Hebrew/', $x); });
    if ($fatal) throw new Exception('Claude לא החזיר טקסט תקין (' . implode(', ', $fatal) . ')');
    $p['warnings'] = array_merge($p['warnings'], $problems);
    $p['content'] = $content;
    $p['write_feedback'] = '';
    $p['stage'] = 'save';
    nps_set_status($p, 'save', ['name' => $content['name']]);
}

// USD per million tokens; batch jobs cost half. Web search: $10 per 1,000 searches.
function nps_add_cost(&$p, $result, $batch) {
    $u = ($result && $result['type'] === 'succeeded') ? ($result['message']['usage'] ?? null) : null;
    if (!$u) return;
    $price = NPS_PRICES[nps_settings()['model']] ?? NPS_PRICES['claude-sonnet-5'];
    $tokens = ($u['input_tokens'] ?? 0) + 1.25 * ($u['cache_creation_input_tokens'] ?? 0) + 0.1 * ($u['cache_read_input_tokens'] ?? 0);
    $usd = ($tokens * $price[0] + ($u['output_tokens'] ?? 0) * $price[1]) / 1e6 * ($batch ? 0.5 : 1);
    $usd += ($u['server_tool_use']['web_search_requests'] ?? 0) * 0.01;
    $p['cost'] = ($p['cost'] ?? 0) + $usd;
    $run = nps_get('run', []);
    $run['cost'] = ($run['cost'] ?? 0) + $usd;
    nps_set('run', $run);
}

// ---------- starting, fixing, stopping ----------

function nps_queue_links($links) {
    nps_lock(30);
    try {
        if (!nps_active_count()) nps_new_run();
        $run = nps_get('run', []);
        foreach ($links as $l) nps_new_item($l, $run['id'] ?? '');
    } finally {
        nps_unlock();
    }
    nps_set('last_error', '');
    nps_schedule_tick();
    return count($links);
}

function nps_revise($id, $note) {
    $p = nps_item($id);
    if (!$p || empty($p['content'])) return 'אי אפשר לתקן את המוצר הזה. סורקים אותו מחדש.';
    if (in_array($p['stage'], NPS_ACTIVE_STAGES, true)) return 'המוצר עדיין בעבודה.';
    nps_lock(30);
    try {
        if (!nps_active_count()) nps_new_run();
        global $wpdb;
        $wpdb->update(nps_table(), ['stage' => 'write_pending'], ['id' => $id]);   // "stopped" items can be fixed too
        $p['revision'] = ['note' => $note, 'previous' => $p['content']];
        $p['stage'] = 'write_pending';
        $p['write_attempts'] = 0;
        $p['step_tries'] = [];
        $p['direct_tries'] = [];
        $p['use_batch'] = [];
        $p['now_errors'] = 0;
        $p['warnings'] = $p['base_warnings'] ?? [];
        nps_set_status($p, 'write', ['notes' => '']);
    } finally {
        nps_unlock();
    }
    nps_schedule_tick();
    return '';
}

function nps_stop_all() {
    nps_lock(60);
    try {
        $s = nps_settings();
        foreach (nps_get('batches', []) as $b) {
            try { nps_claude_request($s, 'POST', '/v1/messages/batches/' . $b['id'] . '/cancel'); } catch (Throwable $e) {}
        }
        nps_set('batches', []);
        global $wpdb;
        $in = "'" . implode("','", NPS_ACTIVE_STAGES) . "'";
        $wpdb->query('UPDATE ' . nps_table() . " SET stage = 'stopped', status = 'stopped' WHERE stage IN ($in)");
        if (function_exists('as_unschedule_all_actions')) as_unschedule_all_actions(NPS_TICK_HOOK, [], NPS_GROUP);
        else wp_clear_scheduled_hook(NPS_TICK_HOOK);
    } finally {
        nps_unlock();
    }
}

function nps_new_run() {
    $u = wp_get_current_user();
    nps_set('run', ['id' => uniqid('r'), 'cost' => 0, 'email' => $u->user_email ?? '', 'user' => $u->ID ?? 0, 'mailed' => false]);
}

function nps_finish_run() {
    $run = nps_get('run', []);
    if (!$run || !empty($run['mailed'])) return;
    $run['mailed'] = true;
    nps_set('run', $run);
    if (!nps_settings()['email'] || empty($run['email'])) return;
    global $wpdb;
    $n = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM ' . nps_table() . " WHERE run_id = %s AND stage = 'done'", $run['id']));
    wp_mail($run['email'], 'סורק מוצרים: הסריקה הסתיימה', $n . " מוצרים מוכנים בחנות כטיוטות.\n\n" . admin_url('edit.php?post_type=product&page=nps-scraper'));
}
