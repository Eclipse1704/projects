<?php
// Settings: defaults + what the user changed on the settings screen (option nps_settings).
// The Claude API key is kept apart (option nps_api_key, not autoloaded).

if (!defined('ABSPATH')) exit;

define('NPS_SHORT_MAX_WORDS', 80);
define('NPS_FULL_MAX_WORDS', 500);

function nps_default_settings() {
    return [
        'model' => 'claude-sonnet-5',
        'fast' => 'yes',
        'email' => 'yes',
        'publish_status' => 'draft',
        'style_urls' => '',
        'glossary' => implode("\n", [
            'thermal camera = מצלמה תרמית',
            'thermal sensitivity / NETD = רגישות תרמית',
            'IR resolution = רזולוציית חיישן (למשל 640X480 פיקסלים)',
            'temperature range = טווח מדידת טמפרטורה',
            'water leak detection = איתור נזילות מים',
            'acoustic leak detector = מכשיר אקוסטי לאיתור נזילות',
            'tracer gas (hydrogen) = גז מימן / איתור נזילות בגז',
            'underground / under-floor pipes = צנרת תת-קרקעית / צנרת מתחת לריצוף',
            'pipe inspection camera / push camera = מצלמת צנרת / מצלמת ביוב',
            'videoscope = וידאוסקופ',
            'borescope = בורוסקופ',
            'fiberscope = פייברסקופ',
            'articulation = היגוי (ראש מתכוונן)',
            'probe / insertion tube = פרוב / צינור החדרה',
            'non-destructive testing (NDT) = בדיקות לא הורסות',
            'correlator = קורלטור',
        ]),
        'avoid_words' => implode("\n", ['הינו', 'הינה', 'הינם', 'הנו', 'מהפכני', 'מהפכנית', 'פורץ דרך', 'פתרון מושלם', 'יתר על כן', 'בנוסף לכך', 'באופן משמעותי', 'חווית משתמש']),
        // Where the theme keeps the "קטלוג pdf", "ספר הוראות" and "וידאו מוצר" fields (found automatically).
        'field_catalog' => '',
        'field_manual' => '',
        'field_video' => '',
    ];
}

function nps_settings() {
    if (!empty($GLOBALS['nps_settings_memo'])) return $GLOBALS['nps_settings_memo'];
    $saved = get_option('nps_settings', []);
    $map = nps_default_settings();
    foreach ((array) $saved as $k => $v) {
        if (array_key_exists($k, $map) && trim((string) $v) !== '') $map[$k] = trim((string) $v);
    }
    $map['fast'] = $map['fast'] !== 'no';
    $map['email'] = $map['email'] !== 'no';
    $map['avoid_list'] = array_values(array_filter(array_map('trim', explode("\n", $map['avoid_words']))));
    $map['style_list'] = array_values(array_filter(preg_split('/\s+/', $map['style_urls']), function ($u) { return preg_match('#^https?://#', $u); }));
    $map['api_key'] = (string) get_option('nps_api_key', '');
    $map['api_base'] = defined('NPS_API_BASE') ? NPS_API_BASE : 'https://api.anthropic.com';
    $GLOBALS['nps_settings_memo'] = $map;
    return $map;
}

// Keeps only values that differ from the defaults, so improved defaults still reach this site.
function nps_save_settings($values) {
    $defaults = nps_default_settings();
    $out = [];
    foreach ($defaults as $k => $def) {
        if (!isset($values[$k])) continue;
        $v = trim(str_replace("\r", '', wp_unslash((string) $values[$k])));
        if ($v !== '' && $v !== trim($def)) $out[$k] = $v;
    }
    update_option('nps_settings', $out, false);
    nps_forget_settings();
}

function nps_forget_settings() { $GLOBALS['nps_settings_memo'] = null; }

foreach (['nps_settings', 'nps_api_key'] as $o) {
    add_action('update_option_' . $o, 'nps_forget_settings');
    add_action('add_option_' . $o, 'nps_forget_settings');
    add_action('delete_option_' . $o, 'nps_forget_settings');
}
