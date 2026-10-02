<?php
// Claude API over HTTP: direct calls (several at once) and the Message Batches API (half price, no time limit).

if (!defined('ABSPATH')) exit;

function nps_claude_headers($s) {
    return ['x-api-key' => $s['api_key'], 'anthropic-version' => '2023-06-01', 'content-type' => 'application/json'];
}

function nps_claude_error($code, $body) {
    $j = json_decode($body, true);
    $msg = 'Claude API ' . $code . ': ' . ($j['error']['message'] ?? mb_substr(wp_strip_all_tags((string) $body), 0, 200));
    if ($code === 401) $msg .= ' (מפתח ה-API לא תקין - מחליפים אותו בהגדרות)';
    return $msg;
}

// Throws on failure (with ->status). For batch management.
function nps_claude_request($s, $method, $path, $body = null) {
    $r = nps_http($method, $s['api_base'] . $path, ['headers' => nps_claude_headers($s), 'body' => $body === null ? null : wp_json_encode($body), 'timeout' => 60, 'trusted' => true]);
    if (!$r['code'] || $r['code'] >= 400) {
        $e = new NPS_Http_Error($r['code'] ? nps_claude_error($r['code'], $r['body']) : 'Claude API: ' . $r['error']);
        $e->status = $r['code'];
        throw $e;
    }
    return $r['body'] === '' ? [] : json_decode($r['body'], true);
}

class NPS_Http_Error extends Exception { public $status = 0; public $wpcode = ''; }

// Several messages at the same time. Each answer: ['result' => [type succeeded|errored, ...], 'status' => int, 'timeout' => bool].
function nps_claude_now($s, $paramsList) {
    $reqs = [];
    foreach ($paramsList as $p) {
        $reqs[] = ['method' => 'POST', 'url' => $s['api_base'] . '/v1/messages', 'headers' => nps_claude_headers($s), 'body' => wp_json_encode($p), 'timeout' => 290];
    }
    $out = [];
    foreach (nps_http_multi($reqs) as $i => $r) {
        if (!$r['code']) { $out[$i] = ['timeout' => true, 'message' => $r['error']]; continue; }
        $body = json_decode($r['body'], true);
        if ($r['code'] < 400 && is_array($body)) { $out[$i] = ['result' => ['type' => 'succeeded', 'message' => $body]]; continue; }
        $msg = nps_claude_error($r['code'], $r['body']);
        $out[$i] = ['status' => $r['code'], 'message' => $msg, 'result' => ['type' => 'errored', 'error' => ['error' => ['message' => $msg]]]];
    }
    return $out;
}

function nps_batch_results($s, $batch) {
    $r = nps_http('GET', $batch['results_url'], ['headers' => nps_claude_headers($s), 'timeout' => 120, 'trusted' => true]);
    if (!$r['code'] || $r['code'] >= 400) throw new Exception('Claude API results ' . $r['code']);
    $out = [];
    foreach (explode("\n", $r['body']) as $l) if (trim($l) !== '') $out[] = json_decode($l, true);
    return $out;
}

function nps_message_text($m) {
    $t = '';
    foreach (($m['content'] ?? []) as $b) if (($b['type'] ?? '') === 'text') $t .= $b['text'];
    return $t;
}

// ---------- Who makes it, and where is the official site ----------

function nps_research_params($s, $p) {
    $page = $p['supplier'] ?? [];
    $q = 'Product page: ' . $p['link'] . "\n" .
        (!empty($page['title']) ? 'Product name on the page: ' . $page['title'] . "\n" : '') .
        (!empty($page['text']) ? "Page text (excerpt):\n" . mb_substr($page['text'], 0, 5000) . "\n" : "(The page could not be downloaded directly - fetch it yourself.)\n") .
        "\nFind, using web search and web fetch:\n" .
        "1. The manufacturer (brand owner) of this product and ALL domains of its OFFICIAL websites. Distributors, resellers, marketplaces and review sites are NOT official.\n" .
        "2. The product's own page on the manufacturer's official website.\n" .
        "3. An official page that lists downloads for this product (brochure / datasheet / user manual), if there is one.\n" .
        '4. Whether ' . nps_host($p['link']) . " is itself the manufacturer's official site.\n" .
        "Only report URLs you actually saw. Finish with ONLY this JSON (no other text after it):\n" .
        "```json\n{\"manufacturer\": \"\", \"model\": \"\", \"official_domains\": [], \"official_product_url\": \"\", \"official_downloads_url\": \"\", \"site_is_manufacturer\": false}\n```\n" .
        'manufacturer = brand name as the manufacturer writes it (e.g. "FOTRIC"); model = model name without the brand (e.g. "348A"); use "" when not found.' .
        ($s['fast'] ? "\nWork quickly: usually one or two searches are enough. Use web_fetch only if the search results don't show the URLs you need - the pages themselves are read later by other code." : '');
    $params = [
        'model' => $s['model'],
        'max_tokens' => 16000,
        'tools' => [
            ['type' => 'web_search_20260209', 'name' => 'web_search', 'max_uses' => $s['fast'] ? 4 : 6],
            ['type' => 'web_fetch_20260209', 'name' => 'web_fetch', 'max_uses' => $s['fast'] ? 2 : 6],
        ],
        'messages' => [['role' => 'user', 'content' => $q]],
    ];
    if ($s['fast']) $params['output_config'] = ['effort' => 'medium'];
    return $params;
}

function nps_parse_research($m) {
    $t = nps_message_text($m);
    if (!preg_match('/```json\s*([\s\S]*?)```/', $t, $mm) && !preg_match('/(\{[\s\S]*"official_domains"[\s\S]*\})/', $t, $mm)) return null;
    $r = json_decode($mm[1], true);
    if (!is_array($r)) return null;
    return [
        'manufacturer' => trim((string) ($r['manufacturer'] ?? '')),
        'model' => trim((string) ($r['model'] ?? '')),
        'official_domains' => nps_clean_domains($r['official_domains'] ?? []),
        'official_product_url' => trim((string) ($r['official_product_url'] ?? '')),
        'official_downloads_url' => trim((string) ($r['official_downloads_url'] ?? '')),
        'site_is_manufacturer' => ($r['site_is_manufacturer'] ?? false) === true,
    ];
}

// ---------- Write the Hebrew entry and choose the files ----------

// The fields of the "add product" screen. Slug, SEO title and meta description are left to WordPress / Yoast,
// like on every other product of the site.
function nps_write_schema() {
    return [
        'type' => 'object',
        'additionalProperties' => false,
        'required' => ['name', 'short_description', 'description_paragraphs', 'usage', 'specs', 'category', 'tags', 'focus_keyphrase', 'image_indexes', 'brochure_index', 'manual_index', 'video_indexes'],
        'properties' => [
            'name' => ['type' => 'string', 'description' => "Hebrew product title in the house style, e.g. 'מצלמה תרמית לסמארטפון 320X240 פיקסלים Fotric TP320A'"],
            'short_description' => ['type' => 'string', 'description' => 'Hebrew, one paragraph, at most ' . NPS_SHORT_MAX_WORDS . ' words (usually 45-65): what it is and how it works, who it is for, one standout advantage'],
            'description_paragraphs' => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'the full description: 2-4 Hebrew paragraphs of running text (no headings, no lists)'],
            'usage' => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'Hebrew bullet list of applications (4-8 short lines), shown after the paragraphs'],
            'specs' => ['type' => 'array', 'description' => 'key technical specifications for internal reference (not shown on the site - the full spec is in the catalog PDF); Hebrew labels, values as in the source',
                'items' => ['type' => 'object', 'additionalProperties' => false, 'required' => ['name', 'value'], 'properties' => ['name' => ['type' => 'string'], 'value' => ['type' => 'string']]]],
            'category' => ['type' => 'string', 'description' => 'exactly one name from <site_categories> that fits this product, or "" if none fits'],
            'tags' => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => '3-6 short Hebrew product tags (product type, use, brand)'],
            'focus_keyphrase' => ['type' => 'string', 'description' => 'Yoast focus keyphrase: what a customer in Israel would search for, e.g. "מצלמה תרמית לסמארטפון"'],
            'image_indexes' => ['type' => 'array', 'items' => ['type' => 'integer'], 'description' => 'indexes of up to 8 photos of THIS product, best first (the first is the main product image; the first 3-5 high-resolution ones are kept). No logos, icons, banners, certificates, other products or accessories'],
            'brochure_index' => ['type' => 'integer', 'description' => "index of the PDF that is this product's brochure / datasheet / catalogue, or -1"],
            'manual_index' => ['type' => 'integer', 'description' => "index of the PDF that is this product's user manual, or -1"],
            'video_indexes' => ['type' => 'array', 'items' => ['type' => 'integer'], 'description' => 'indexes of YouTube videos that demonstrate THIS product, best first'],
        ],
    ];
}

const NPS_PAGE_STRUCTURE_EXAMPLE = "name: מצלמה תרמית לסמארטפון 320X240 פיקסלים Fotric TP320A\n\n" .
    "short_description: מצלמה תרמית קטנה שמתחברת ישירות לחיבור USB-C בטלפון אנדרואיד והופכת אותו למצלמת אינפרה אדום מקצועית תוך שניות, בלי סוללה ובלי זמן אתחול. מתאימה לחשמלאים, טכנאי מיזוג ובודקי בתים שצריכים לאתר נקודות חום בלוחות חשמל, מנועים ומערכות מיזוג. תומכת בתוכנת AnalyzIR לניתוח מתקדם במחשב וביצירת דוחות.\n\n" .
    "description_paragraphs:\n" .
    "1. Fotric TP320A היא מצלמה תרמית פלאג-אנד-פליי שמתחברת ישירות לחיבור USB-C בטלפון אנדרואיד והופכת אותו למצלמת אינפרה אדום מלאה תוך שניות. אין צורך בסוללה נפרדת, בזמן אתחול או בהגדרות מסובכות - מחברים את המצלמה, פותחים את אפליקציית FOTRIC Genie ומתחילים לסרוק.\n" .
    "2. המצלמה מבוססת על חיישן ברזולוציה 320X240 פיקסלים עם רזולוציית-על (Super Resolution) שמגיעה עד 640X480 פיקסלים, ורגישות תרמית (NETD) גבוהה של פחות מ-35mK. השילוב מאפשר לזהות הפרשי טמפרטורה קטנים מאוד בלוחות חשמל, מנועים ומערכות מיזוג אוויר. טווח מדידת הטמפרטורה הרחב - מ-20°C- עד 550°C - מתאים גם לעבודות תעשייתיות וגם לבדיקות ביתיות.\n" .
    "3. הגוף קומפקטי מאוד, במשקל 40 גרם בלבד ובמידות 71X33X15.5 מ\"מ, ונכנס בקלות לכיס, לתיק כלים או לתרמיל. דרגת אטימות IP40 ועמידות בנפילה מגובה מטר הופכות אותה למכשיר שעומד גם בתנאי שטח.\n\n" .
    "usage:\n- בדיקת לוחות חשמל ואיתור נקודות חמות לפני שהופכות לתקלה\n- מעקב אחרי טמפרטורת מנועים וציוד מכני\n- אבחון מערכות מיזוג ואוורור (HVAC) ובדיקת פתחי אוויר\n- ביקורות אנרגיה בבתים ואיתור בעיות בידוד";

function nps_system_prompt($s, $examples, $categories) {
    $ex = '';
    foreach ($examples as $i => $e) $ex .= '<example index="' . ($i + 1) . '" url="' . $e['url'] . "\">\n" . $e['text'] . "\n</example>\n";
    return "את/ה קופירייטר/ית טכני/ת בכיר/ה בחנות שמוכרת ציוד מקצועי לבדיקות לא הורסות (NDT), איתור נזילות מים, מצלמות צנרת, וידאוסקופים ומצלמות תרמיות.\n" .
        "המשימה: לכתוב דף מוצר בעברית לחנות, על סמך חומר מקור באנגלית (או בשפה אחרת) מאתר הספק, מאתר היצרן ומהברושור שלו, ולבחור את התמונות, הקבצים והסרטונים של המוצר.\n\n" .
        "איך כותבים:\n" .
        "- עברית טבעית, עכשווית ומקצועית - כמו שטכנאי או איש מכירות בתחום בישראל מדבר וכותב היום. לא תרגום מילולי, לא לשון גבוהה או ארכאית, ולא מילים עבריות \"מומצאות\" שאף אחד בענף לא משתמש בהן.\n" .
        "- כשבענף בישראל משתמשים במונח הלועזי (למשל וידאוסקופ, פרוב, Wi-Fi, NETD, IP54) - משתמשים בו. שמות מותגים, דגמים, יחידות, תקנים ופרוטוקולים נשארים באותיות לטיניות.\n" .
        "- להשתמש במונחים מרשימת המונחים ומדוגמאות הסגנון (מוצרים קיימים בחנות). הדוגמאות הן המקור הקובע לסגנון, לטון ולאוצר המילים - לא לתוכן.\n" .
        "- כותרת המוצר (name) בפורמט של החנות: סוג המוצר בעברית + נתון מפתח אם רלוונטי + מותג + דגם. לדוגמה: \"מצלמה תרמית 640X480 פיקסלים Fotric 348A\", \"Sniffer430 מכשיר לאיתור נזילות מים בגז\".\n" .
        "- משפטים קצרים וברורים, בגוף פעיל. כותבים כמו טכנאי מנוסה שמסביר ללקוח מקצועי מה המכשיר עושה ולמה הוא טוב לו - בלי מליצות ובלי שפה שיווקית מתורגמת.\n" .
        "- לא לתרגם מילה במילה מאנגלית. לדוגמה: לא \"המכשיר הינו פתרון מושלם עבור...\" אלא \"המכשיר מתאים ל...\"; לא \"מספק למשתמש יכולת לבצע איתור\" אלא \"מאתר\"; לא \"חווית משתמש אינטואיטיבית\" אלא \"תפעול פשוט\".\n" .
        "- לא להשתמש במילים ובביטויים שברשימה <avoid_words>.\n" .
        '- short_description: פסקה אחת, עד ' . NPS_SHORT_MAX_WORDS . " מילים (בדרך כלל 45-65): מה המוצר ואיך הוא עובד, למי הוא מתאים, ויתרון בולט אחד.\n" .
        '- התיאור המלא בנוי כמו בדפים בחנות: description_paragraphs = 2-4 פסקאות טקסט רציף (בלי כותרות ובלי רשימות), ואחריהן usage = רשימת שימושים קצרה. הנתונים הטכניים החשובים (רזולוציה, רגישות, טווחים, מידות, משקל, אטימות) משולבים בתוך המשפטים. ביחד עד ' . NPS_FULL_MAX_WORDS . " מילים. אין טבלת מפרט בדף - המפרט המלא נמצא בקטלוג ה-PDF; specs הוא רק רשימה פנימית לעיון.\n" .
        "- פסקה 1: מה המוצר ואיך מתחילים לעבוד איתו. פסקה 2: הנתונים הטכניים המרכזיים ומה הם נותנים בעבודה. פסקה 3: גוף, משקל, עמידות, אביזרים ותוכנה (רק מה שמופיע במקור).\n" .
        "- focus_keyphrase (Yoast) = מה שלקוח בישראל היה מחפש בגוגל כדי למצוא את המוצר.\n" .
        "- category: בוחרים בדיוק שם אחד מתוך <site_categories>. tags: 3-6 תגיות קצרות בעברית.\n\n" .
        "<page_structure_example>\n" . NPS_PAGE_STRUCTURE_EXAMPLE . "\n</page_structure_example>\n\n" .
        "עובדות:\n" .
        "- רק עובדות שמופיעות בחומר המקור. אסור להמציא נתונים, מספרים, תקנים, אחריות או טענות. מה שלא מופיע - לא נכתב.\n" .
        "- כשיש סתירה, עדיף המידע מאתר היצרן הרשמי ומהברושור שלו.\n" .
        "- בלי מחירים, בלי פרטי התקשרות, בלי סופרלטיבים שלא מופיעים במקור.\n\n" .
        "לפני שמחזירים תשובה: קוראים שוב כל משפט בעברית. משפט שנשמע מתורגם, מסורבל או לא כמו שאומרים בענף - כותבים מחדש.\n\n" .
        "בחירת קבצים: בוחרים רק מתוך הרשימות הממוספרות (כולן מאתר היצרן הרשמי). אם אין פריט מתאים - רשימה ריקה או -1.\n\n" .
        "<glossary>\n" . $s['glossary'] . "\n</glossary>\n\n<avoid_words>\n" . implode("\n", $s['avoid_list']) . "\n</avoid_words>\n\n" .
        "<site_categories>\n" . (implode("\n", $categories) ?: '(no categories - leave category empty)') . "\n</site_categories>\n\n" .
        "<style_examples>\n" . ($ex ?: '(no examples)') . '</style_examples>';
}

function nps_write_params($s, $p, $examples, $categories, $brochure64, $feedback) {
    $off = $p['official'] ?? ['images' => [], 'pdfs' => [], 'videos' => [], 'pages' => []];
    $parts = ['Manufacturer: ' . $p['research']['manufacturer'], 'Model: ' . $p['research']['model'], 'Product link: ' . $p['link']];
    foreach ($off['pages'] as $pg) $parts[] = "\n=== OFFICIAL MANUFACTURER PAGE: " . $pg['url'] . " ===\n" . $pg['text'];
    if (!empty($p['supplier']['text']) && empty($p['research']['site_is_manufacturer'])) $parts[] = "\n=== SUPPLIER PAGE: " . $p['link'] . " ===\n" . $p['supplier']['text'];
    $sources = mb_substr(implode("\n", $parts), 0, 60000);
    $lists = "<images>\n";
    foreach ($off['images'] as $i => $im) $lists .= $i . "\t" . $im['url'] . "\t" . ($im['alt'] ?? '') . "\t" . ($im['where'] ?? '') . "\n";
    $lists .= "</images>\n<pdfs>\n";
    foreach ($off['pdfs'] as $i => $d) $lists .= $i . "\t" . $d['url'] . "\t" . ($d['label'] ?? '') . "\n";
    $lists .= "</pdfs>\n<videos>\n";
    foreach ($off['videos'] as $i => $v) $lists .= $i . "\t" . $v['url'] . "\t" . ($v['title'] ?? '') . "\n";
    $lists .= '</videos>';
    $content = [];
    if ($brochure64) $content[] = ['type' => 'document', 'title' => 'Official brochure', 'source' => ['type' => 'base64', 'media_type' => 'application/pdf', 'data' => $brochure64]];
    $ask = 'כתוב/י את דף המוצר ובחר/י את התמונות, הקבצים והסרטונים.';
    if (!empty($p['revision'])) {
        $ask = "<previous_version>\n" . wp_json_encode($p['revision']['previous'], JSON_UNESCAPED_UNICODE) . "\n</previous_version>\n\n" .
            "<requested_changes>\n" . $p['revision']['note'] . "\n</requested_changes>\n\n" .
            'זו גרסה שכבר נכתבה למוצר. עדכן/י אותה לפי הבקשה, ושמור/י על כל השאר כמו שהוא (גם על בחירת התמונות, הקבצים והסרטונים, אלא אם הבקשה היא לשנות אותם). ' .
            'גם בתיקון כותבים רק עובדות שמופיעות במקורות. אם הבקשה דורשת עובדה שלא מופיעה במקורות, לא ממציאים אותה.';
    }
    $content[] = ['type' => 'text', 'text' => "<sources>\n" . $sources . "\n</sources>\n\n" . $lists . "\n\n" . $ask . ($feedback ?: '')];
    return [
        'model' => $s['model'],
        'max_tokens' => 16000,
        'system' => [['type' => 'text', 'text' => nps_system_prompt($s, $examples, $categories), 'cache_control' => ['type' => 'ephemeral']]],
        'messages' => [['role' => 'user', 'content' => $content]],
        'output_config' => ['effort' => $s['fast'] ? 'medium' : 'high', 'format' => ['type' => 'json_schema', 'schema' => nps_write_schema()]],
    ];
}

function nps_word_count($s) {
    return preg_match_all('/\S+/u', (string) $s);
}

// Hebrew word match (\b doesn't work for Hebrew letters).
function nps_contains_word($text, $word) {
    return (bool) preg_match('/(^|[^\x{0590}-\x{05FF}])' . preg_quote($word, '/') . '(?=$|[^\x{0590}-\x{05FF}])/u', $text);
}

function nps_validate_content($c, $avoid) {
    $problems = [];
    foreach (['name', 'short_description'] as $k) if (trim((string) ($c[$k] ?? '')) === '') $problems[] = 'missing ' . $k;
    $paras = array_filter(array_map('trim', (array) ($c['description_paragraphs'] ?? [])));
    if (!$paras) $problems[] = 'missing description_paragraphs';
    $sw = nps_word_count($c['short_description'] ?? '');
    if ($sw > NPS_SHORT_MAX_WORDS) $problems[] = 'short_description has ' . $sw . ' words (max ' . NPS_SHORT_MAX_WORDS . ')';
    $full = array_merge((array) ($c['description_paragraphs'] ?? []), (array) ($c['usage'] ?? []));
    $fw = 0;
    foreach ($full as $x) $fw += nps_word_count($x);
    if ($fw > NPS_FULL_MAX_WORDS) $problems[] = 'full description (description_paragraphs + usage) has ' . $fw . ' words (max ' . NPS_FULL_MAX_WORDS . ')';
    if (!preg_match('/[\x{0590}-\x{05FF}]/u', ($c['short_description'] ?? '') . implode(' ', $paras))) $problems[] = 'texts are not in Hebrew';
    $all = implode("\n", array_merge([$c['name'] ?? '', $c['short_description'] ?? ''], $full, (array) ($c['tags'] ?? [])));
    $used = array_values(array_filter($avoid, function ($w) use ($all) { return nps_contains_word($all, $w); }));
    if ($used) $problems[] = 'uses words from <avoid_words>: ' . implode(', ', $used) . ' - rewrite those sentences';
    return $problems;
}

function nps_tidy_content($c, $categories) {
    $c['tags'] = array_slice(array_values(array_filter(array_map(function ($t) { return trim((string) $t); }, (array) ($c['tags'] ?? [])))), 0, 8);
    if (!in_array($c['category'] ?? '', $categories, true)) $c['category'] = '';
    return $c;
}

// Existing products of the shop, as examples of style (unless the settings name pages).
function nps_style_examples($s) {
    $key = 'nps_style_' . md5(implode(' ', $s['style_list']));
    $hit = get_transient($key);
    if (is_array($hit)) return $hit;
    $out = [];
    foreach ($s['style_list'] as $u) {
        $id = url_to_postid($u);
        if ($id && get_post_type($id) === 'product') {
            $p = get_post($id);
            $out[] = ['url' => $u, 'text' => mb_substr(wp_strip_all_tags($p->post_title . "\n\n" . $p->post_excerpt . "\n\n" . $p->post_content), 0, 5000)];
            continue;
        }
        $page = nps_fetch_page($u);
        if ($page) $out[] = ['url' => $u, 'text' => mb_substr($page['text'], 0, 5000)];
    }
    if (!$s['style_list']) {
        $q = new WP_Query(['post_type' => 'product', 'post_status' => 'publish', 'posts_per_page' => 20, 'orderby' => 'modified', 'order' => 'DESC', 'no_found_rows' => true,
            'meta_query' => [['key' => '_nps_source_link', 'compare' => 'NOT EXISTS']]]);
        foreach ($q->posts as $p) {
            if (count($out) >= 3) break;
            if (mb_strlen(wp_strip_all_tags($p->post_content)) < 600) continue;
            $out[] = ['url' => get_permalink($p), 'text' => mb_substr(trim(wp_strip_all_tags($p->post_title . "\n\n" . $p->post_excerpt . "\n\n" . $p->post_content)), 0, 5000)];
        }
    }
    set_transient($key, $out, 6 * HOUR_IN_SECONDS);
    return $out;
}
