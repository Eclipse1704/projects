<?php
// The list of products: one row per link (table {prefix}nps_items). Each row keeps the product's whole
// pipeline state as JSON, plus the columns the screen shows.

if (!defined('ABSPATH')) exit;

const NPS_DB_VERSION = '1';

function nps_table() {
    global $wpdb;
    return $wpdb->prefix . 'nps_items';
}

function nps_install() {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta('CREATE TABLE ' . nps_table() . " (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id varchar(40) NOT NULL DEFAULT '',
  link text NOT NULL,
  stage varchar(30) NOT NULL DEFAULT 'new',
  status varchar(30) NOT NULL DEFAULT 'queued',
  name text NOT NULL,
  manufacturer varchar(200) NOT NULL DEFAULT '',
  product_id bigint(20) unsigned NOT NULL DEFAULT 0,
  notes text NOT NULL,
  cost double NOT NULL DEFAULT 0,
  state longtext NOT NULL,
  created datetime NOT NULL,
  updated datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY stage (stage)
) " . $wpdb->get_charset_collate() . ';');
    update_option('nps_db_version', NPS_DB_VERSION);
}

function nps_maybe_upgrade() {
    if (wp_installing()) return;
    if (get_option('nps_db_version') !== NPS_DB_VERSION) nps_install();
}

const NPS_ACTIVE_STAGES = ['new', 'research_pending', 'research_wait', 'official', 'write_pending', 'write_wait', 'save'];

function nps_row_to_item($row) {
    $p = json_decode($row->state, true) ?: [];
    $p['id'] = (int) $row->id;
    $p['link'] = $row->link;
    $p['stage'] = $row->stage;
    $p['status'] = $row->status;
    $p['run_id'] = $row->run_id;
    $p['product_id'] = (int) $row->product_id;
    $p['cost'] = (float) $row->cost;
    $p['row'] = ['name' => $row->name, 'manufacturer' => $row->manufacturer, 'notes' => $row->notes, 'created' => $row->created];
    return $p;
}

function nps_item($id) {
    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . nps_table() . ' WHERE id = %d', $id));
    return $row ? nps_row_to_item($row) : null;
}

function nps_items_in($stages) {
    global $wpdb;
    $in = implode(',', array_fill(0, count($stages), '%s'));
    $rows = $wpdb->get_results($wpdb->prepare('SELECT * FROM ' . nps_table() . " WHERE stage IN ($in) ORDER BY id", $stages));
    return array_map('nps_row_to_item', $rows);
}

function nps_active_count() {
    global $wpdb;
    $in = "'" . implode("','", NPS_ACTIVE_STAGES) . "'";
    return (int) $wpdb->get_var('SELECT COUNT(*) FROM ' . nps_table() . " WHERE stage IN ($in)");
}

function nps_new_item($link, $run_id) {
    global $wpdb;
    $now = current_time('mysql', true);
    $wpdb->insert(nps_table(), [
        'run_id' => $run_id, 'link' => $link, 'stage' => 'new', 'status' => 'queued', 'name' => '', 'manufacturer' => '', 'notes' => '',
        'state' => wp_json_encode(['warnings' => [], 'step_tries' => [], 'write_attempts' => 0, 'research_attempts' => 0]), 'created' => $now, 'updated' => $now,
    ]);
    return (int) $wpdb->insert_id;
}

// Saves an item. Columns shown on the screen can be set through $show (name, manufacturer, notes).
// A product the user stopped meanwhile stays stopped.
function nps_save_item(&$p, $show = []) {
    global $wpdb;
    $state = $p;
    foreach (['id', 'link', 'stage', 'status', 'run_id', 'product_id', 'cost', 'row'] as $k) unset($state[$k]);
    $data = ['stage' => $p['stage'], 'status' => $p['status'], 'product_id' => (int) ($p['product_id'] ?? 0), 'cost' => (float) ($p['cost'] ?? 0),
        'state' => wp_json_encode($state, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), 'updated' => current_time('mysql', true)];
    foreach (['name', 'manufacturer', 'notes'] as $k) if (isset($show[$k])) $data[$k] = mb_substr((string) $show[$k], 0, 1000);
    $set = [];
    $vals = [];
    foreach ($data as $k => $v) { $set[] = "$k = " . (is_float($v) ? '%f' : (is_int($v) ? '%d' : '%s')); $vals[] = $v; }
    $vals[] = $p['id'];
    $wpdb->query($wpdb->prepare('UPDATE ' . nps_table() . ' SET ' . implode(', ', $set) . " WHERE id = %d AND stage <> 'stopped'", $vals));
}

function nps_list_items($limit = 60) {
    global $wpdb;
    $rows = $wpdb->get_results($wpdb->prepare('SELECT * FROM ' . nps_table() . ' ORDER BY id DESC LIMIT %d', $limit));
    return array_map('nps_row_to_item', $rows);
}

// ---- small shared state (options, not autoloaded) ----

function nps_get($key, $default = null) { return get_option('nps_' . $key, $default); }
function nps_set($key, $value) { update_option('nps_' . $key, $value, false); }

// One worker at a time: a row that only one process can insert (INSERT IGNORE on the unique option name).
function nps_lock($wait = 0) {
    global $wpdb;
    $until = time() + $wait;
    while (true) {
        $ok = $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES ('nps_lock', %s, 'no')", (string) time()));
        if ($ok === 1) return true;
        $t = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'nps_lock'");
        if ($t === null) continue;
        if ((int) $t < time() - 900) {   // a worker that died long ago
            $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = 'nps_lock' AND option_value = %s", $t));
            continue;
        }
        if (time() >= $until) return false;
        sleep(1);
    }
}

function nps_unlock() {
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name = 'nps_lock'");
    wp_cache_delete('nps_lock', 'options');
}
