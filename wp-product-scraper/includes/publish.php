<?php
// The last step: the product goes into the shop (a draft by default) with all its fields, images and files.

if (!defined('ABSPATH')) exit;

const NPS_MIN_IMAGE_SIDE = 800;
const NPS_BRAND_TAXONOMIES = ['product_brand', 'pwb-brand', 'yith_product_brand', 'berocket_brand', 'brand'];

// MANUFACTURER-MODEL, upper-case, without repeating the manufacturer.
function nps_slug_part($s) {
    $s = remove_accents((string) $s);
    return trim(preg_replace('/[^A-Za-z0-9]+/', '-', $s), '-');
}

function nps_file_stem($manufacturer, $model) {
    $m = strtoupper(nps_slug_part($manufacturer));
    $p = strtoupper(nps_slug_part($model));
    if ($m && strpos($p, $m . '-') === 0) $p = substr($p, strlen($m) + 1);
    if ($m && $p === $m) $p = '';
    return implode('-', array_filter([$m, $p])) ?: 'PRODUCT';
}

function nps_unique_indexes($list, $n) {
    $out = [];
    foreach ((array) $list as $i) { $i = (int) $i; if ($i >= 0 && $i < $n && !in_array($i, $out, true)) $out[] = $i; }
    return $out;
}

function nps_site_categories() {
    $terms = get_terms(['taxonomy' => 'product_cat', 'hide_empty' => false]);
    if (is_wp_error($terms)) return [];
    $out = [];
    foreach ($terms as $t) if ($t->slug !== 'uncategorized') $out[$t->term_id] = html_entity_decode($t->name, ENT_QUOTES, 'UTF-8');
    return $out;
}

function nps_brand_taxonomy() {
    foreach (NPS_BRAND_TAXONOMIES as $t) if (taxonomy_exists($t)) return $t;
    return '';
}

// "תיאור המוצר": paragraphs, then the list of uses.
function nps_description_html($c) {
    $html = '';
    foreach ((array) ($c['description_paragraphs'] ?? []) as $x) if (trim($x) !== '') $html .= '<p>' . esc_html(trim($x)) . "</p>\n";
    $uses = array_filter(array_map('trim', (array) ($c['usage'] ?? [])));
    if ($uses) $html .= "<ul>\n" . implode("\n", array_map(function ($u) { return '<li>' . esc_html($u) . '</li>'; }, $uses)) . "\n</ul>";
    return trim($html);
}

// Where the theme keeps the "קטלוג pdf", "ספר הוראות" and "וידאו מוצר" fields: found from existing products.
function nps_detect_fields() {
    $ids = get_posts(['post_type' => 'product', 'post_status' => 'any', 'numberposts' => 40, 'fields' => 'ids', 'orderby' => 'modified']);
    $score = ['catalog' => [], 'manual' => [], 'video' => []];
    $add = function ($kind, $key, $n) use (&$score) { $score[$kind][$key] = ($score[$kind][$key] ?? 0) + $n; };
    foreach ($ids as $id) {
        foreach (get_post_meta($id) as $key => $vals) {
            if ($key === '' || $key[0] === '_') continue;
            $v = is_string($vals[0] ?? null) ? $vals[0] : '';
            if (preg_match('/catalog|catalogue|brochure|datasheet|קטלוג/iu', $key)) $add('catalog', $key, 5);
            if (preg_match('/manual|guide|instruction|הוראות/iu', $key)) $add('manual', $key, 5);
            if (preg_match('/video|youtube|וידאו/iu', $key)) $add('video', $key, 5);
            if (preg_match('#youtu\.?be|vimeo\.com#i', $v)) $add('video', $key, 1);
            if (preg_match('/^\d+$/', $v) && get_post_mime_type((int) $v) === 'application/pdf' && !preg_match('/manual|guide|instruction|הוראות/iu', $key)) $add('catalog', $key, 1);
            if (preg_match('/\.pdf(\?|$)/i', $v) && !preg_match('/manual|guide|instruction|הוראות/iu', $key)) $add('catalog', $key, 1);
        }
    }
    $out = [];
    foreach ($score as $kind => $keys) { arsort($keys); $out[$kind] = (string) (array_key_first($keys) ?? ''); }
    if ($out['manual'] === $out['catalog']) $out['manual'] = '';
    return $out;
}

function nps_field_keys() {
    $s = nps_settings();
    $keys = ['catalog' => $s['field_catalog'], 'manual' => $s['field_manual'], 'video' => $s['field_video']];
    if (in_array('', $keys, true)) {
        $found = get_transient('nps_detected_fields');
        if (!is_array($found)) { $found = nps_detect_fields(); set_transient('nps_detected_fields', $found, DAY_IN_SECONDS); }
        foreach ($keys as $k => $v) if ($v === '') $keys[$k] = $found[$k] ?? '';
    }
    return $keys;
}

// A custom field: ACF fields need their field reference too, and may hold an attachment ID instead of a URL.
function nps_set_field($product_id, $key, $url, $attachment_id = 0) {
    if (!$key) return;
    $ref = '';
    $sample = get_posts(['post_type' => 'product', 'post_status' => 'any', 'numberposts' => 1, 'fields' => 'ids', 'exclude' => [$product_id],
        'meta_query' => [['key' => '_' . $key, 'value' => 'field_', 'compare' => 'LIKE']]]);
    if ($sample) $ref = (string) get_post_meta($sample[0], '_' . $key, true);
    $value = $url;
    if ($ref && function_exists('acf_get_field')) {
        $f = acf_get_field($ref);
        if ($f && in_array($f['type'], ['file', 'image'], true)) $value = $attachment_id ?: '';
    }
    if ($ref && function_exists('update_field')) { update_field($ref, $value, $product_id); return; }
    update_post_meta($product_id, $key, $value);
    if ($ref) update_post_meta($product_id, '_' . $key, $ref);
}

function nps_require_media() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';
}

// Puts bytes in the media library under $name (reused when the very same file was uploaded before).
function nps_upload(&$p, $bytes, $name, $parent, $alt = '') {
    $hash = md5($bytes);
    $p['media'] = $p['media'] ?? [];
    if (!empty($p['media'][$hash]) && get_post((int) $p['media'][$hash])) return (int) $p['media'][$hash];
    nps_require_media();
    $tmp = wp_tempnam($name);
    file_put_contents($tmp, $bytes);
    $file = ['name' => $name, 'tmp_name' => $tmp];
    $id = media_handle_sideload($file, $parent, $alt ?: null);
    if (is_wp_error($id)) { @unlink($tmp); throw new Exception('העלאה למדיה נכשלה: ' . $id->get_error_message()); }
    if ($alt) update_post_meta($id, '_wp_attachment_image_alt', $alt);
    $p['media'][$hash] = $id;
    return (int) $id;
}

// 3-5 photos: the full-size version of each, biggest first among sizes; small ones only if there aren't 3 big ones.
function nps_pick_images($candidates) {
    $urls = [];
    foreach ($candidates as $im) { $urls[] = $im['url']; if (!empty($im['fallback'])) $urls[] = $im['fallback']; }
    nps_prefetch($urls);
    $good = []; $small = []; $hashes = [];
    foreach ($candidates as $im) {
        if (count($good) >= 5) break;
        $best = null;
        foreach (array_filter([$im['url'], $im['fallback'] ?? '']) as $u) {
            if ($best && !$best['small']) break;
            $r = nps_fetch($u);
            if (!$r || strlen($r['body']) < 5000) continue;
            $size = @getimagesizefromstring($r['body']);
            if (!$size || !in_array($size['mime'], ['image/jpeg', 'image/png', 'image/webp'], true)) continue;
            $hash = md5($r['body']);
            if (isset($hashes[$hash])) continue;
            $cand = ['bytes' => $r['body'], 'mime' => $size['mime'], 'w' => $size[0], 'h' => $size[1], 'hash' => $hash, 'url' => $u, 'small' => max($size[0], $size[1]) < NPS_MIN_IMAGE_SIDE];
            if (!$best || $cand['w'] * $cand['h'] > $best['w'] * $best['h']) $best = $cand;
        }
        if (!$best) continue;
        $hashes[$best['hash']] = true;
        if ($best['small']) $small[] = $best; else $good[] = $best;
    }
    usort($small, function ($a, $b) { return $b['w'] * $b['h'] - $a['w'] * $a['h']; });
    return array_merge($good, count($good) < 3 ? array_slice($small, 0, 3 - count($good)) : []);
}

// The product this link created before (a text fix, or the same link scanned again).
function nps_existing_product($p) {
    if (!empty($p['product_id'])) {
        $post = get_post($p['product_id']);
        if ($post && $post->post_type === 'product' && $post->post_status !== 'trash') return (int) $post->ID;
    }
    $ids = get_posts(['post_type' => 'product', 'post_status' => ['draft', 'pending', 'private', 'publish', 'future'], 'numberposts' => 1, 'fields' => 'ids',
        'meta_query' => [['key' => '_nps_source_link', 'value' => $p['link']]]]);
    return $ids ? (int) $ids[0] : 0;
}

function nps_step_save(&$p) {
    $s = nps_settings();
    $c = $p['content'];
    $off = $p['official'];
    $stem = nps_file_stem($p['research']['manufacturer'], $p['research']['model'] ?: ($p['supplier']['title'] ?? ''));
    if (!$p['research']['manufacturer'] || !$p['research']['model']) $stem .= '-' . $p['id'];
    $p['warnings'] = $p['base_warnings'] ?? ($p['base_warnings'] = $p['warnings']);

    // 1. the product itself first: images and files are attached to it
    $id = nps_existing_product($p);
    $isNew = !$id;
    $product = $id ? wc_get_product($id) : new WC_Product_Simple();
    $product->set_name($c['name']);
    if ($isNew) $product->set_status($s['publish_status'] === 'pending' ? 'pending' : 'draft');
    $product->set_description(nps_description_html($c));
    $product->set_short_description('<p>' . esc_html($c['short_description']) . '</p>');
    $cats = nps_site_categories();
    $catId = $c['category'] ? array_search($c['category'], $cats, true) : false;
    if ($catId) $product->set_category_ids([(int) $catId]);
    $tagIds = [];
    foreach ($c['tags'] ?? [] as $t) {
        $term = term_exists($t, 'product_tag') ?: wp_insert_term($t, 'product_tag');
        if (!is_wp_error($term)) $tagIds[] = (int) $term['term_id'];
    }
    $product->set_tag_ids($tagIds);
    $product->update_meta_data('_nps_source_link', $p['link']);
    if (!empty($c['focus_keyphrase'])) $product->update_meta_data('_yoast_wpseo_focuskw', $c['focus_keyphrase']);
    $id = $product->save();
    $p['product_id'] = $id;

    // 2. images
    $cands = [];
    foreach (nps_unique_indexes($c['image_indexes'] ?? [], count($off['images'])) as $i) $cands[] = $off['images'][$i];
    $chosen = nps_pick_images(array_slice($cands, 0, 8));
    $imageIds = [];
    $p['saved_images'] = [];
    foreach ($chosen as $n => $im) {
        $ext = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'][$im['mime']];
        $name = $stem . '-' . sprintf('%03d', $n + 1) . '.' . $ext;
        $imageIds[] = nps_upload($p, $im['bytes'], $name, $id, $c['name'] . ($n ? ' - ' . ($n + 1) : ''));
        $p['saved_images'][] = ['file' => $name, 'w' => $im['w'], 'h' => $im['h'], 'small' => $im['small']];
    }
    if ($imageIds) {
        $product->set_image_id($imageIds[0]);
        $product->set_gallery_image_ids(array_slice($imageIds, 1));
    }

    // 3. catalog, manual, video
    $fields = nps_field_keys();
    $docs = [];
    foreach (['brochure' => 'brochure_index', 'manual' => 'manual_index'] as $kind => $k) {
        $d = $off['pdfs'][(int) ($c[$k] ?? -1)] ?? null;
        if (!$d) continue;
        $r = nps_fetch($d['url'], true, 60);
        if (!$r || strncmp($r['body'], '%PDF-', 5) !== 0) continue;
        $att = nps_upload($p, $r['body'], $stem . '-' . strtoupper($kind) . '.pdf', $id);
        $docs[$kind] = ['id' => $att, 'url' => wp_get_attachment_url($att), 'source' => $d['url']];
    }
    $videos = [];
    foreach (nps_unique_indexes($c['video_indexes'] ?? [], count($off['videos'])) as $i) $videos[] = $off['videos'][$i]['url'];
    $p['saved_docs'] = $docs;
    $p['saved_videos'] = $videos;
    $id = $product->save();
    nps_set_field($id, $fields['catalog'], $docs['brochure']['url'] ?? '', $docs['brochure']['id'] ?? 0);
    nps_set_field($id, $fields['manual'], $docs['manual']['url'] ?? '', $docs['manual']['id'] ?? 0);
    nps_set_field($id, $fields['video'], $videos[0] ?? '');

    // 4. brand
    $brandTax = nps_brand_taxonomy();
    $brand = trim($p['research']['manufacturer']);
    if ($brandTax && $brand) {
        $match = 0;
        foreach (get_terms(['taxonomy' => $brandTax, 'hide_empty' => false]) as $t) {
            if (!is_wp_error($t) && mb_strtolower(html_entity_decode($t->name)) === mb_strtolower($brand)) $match = (int) $t->term_id;
        }
        wp_set_object_terms($id, $match ? [$match] : [$brand], $brandTax);
    }

    // 5. what's missing
    $w = &$p['warnings'];
    if (count($chosen) < 3) $w[] = 'נמצאו ' . count($chosen) . ' תמונות באתר היצרן (המטרה 3-5)';
    $small = array_filter($p['saved_images'], function ($x) { return $x['small']; });
    if ($small) $w[] = 'תמונות ברזולוציה נמוכה: ' . implode(', ', array_map(function ($x) { return $x['file'] . ' (' . $x['w'] . '×' . $x['h'] . ')'; }, $small));
    if (empty($docs['brochure'])) $w[] = 'לא נמצא קטלוג באתר היצרן';
    if (empty($docs['manual'])) $w[] = 'לא נמצא ספר הוראות באתר היצרן';
    if (!$videos) $w[] = 'לא נמצא סרטון YouTube באתר היצרן';
    if (!$catId) $w[] = 'לבחור קטגוריה';
    if ($brand && !$brandTax) $w[] = 'לבחור מותג (' . $brand . ')';
    if (!$fields['catalog'] || !$fields['manual'] || !$fields['video']) $w[] = 'שדות קטלוג / ספר הוראות / וידאו לא זוהו באתר - למלא ידנית (או להגדיר בהגדרות)';
    unset($w);
}
