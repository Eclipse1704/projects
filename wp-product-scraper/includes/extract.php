<?php
// Reading web pages: title, text, images (full size), PDFs and YouTube links.

if (!defined('ABSPATH')) exit;

const NPS_SKIP_IMG = '/(logo|icon|sprite|placeholder|avatar|badge|flag|payment|favicon|loader|spinner|pixel)/i';
const NPS_MANUAL_WORDS = ['manual', 'user guide', 'userguide', 'user-guide', 'instruction', 'operating', 'handbuch', 'bedienungsanleitung', 'anleitung', 'quick start', 'quickstart', 'guide'];
const NPS_BROCHURE_WORDS = ['brochure', 'datasheet', 'data sheet', 'data-sheet', 'catalog', 'catalogue', 'leaflet', 'flyer', 'prospekt', 'spec sheet', 'specification', 'datenblatt'];

// Responses downloaded ahead of time (several at once), used once by nps_fetch().
$GLOBALS['nps_fetch_cache'] = [];

function nps_fetch_key($url, $redirect) { return nps_encode_url($url) . '|' . ($redirect ? '' : 'no-redirect'); }

function nps_fetch($url, $redirect = true, $timeout = 25) {
    $key = nps_fetch_key($url, $redirect);
    if (array_key_exists($key, $GLOBALS['nps_fetch_cache'])) {
        $hit = $GLOBALS['nps_fetch_cache'][$key];
        unset($GLOBALS['nps_fetch_cache'][$key]);
        return $hit;
    }
    $r = nps_http('GET', $url, ['redirect' => $redirect, 'timeout' => $timeout]);
    return $r['code'] && $r['code'] < 400 ? $r : null;
}

function nps_prefetch($urls, $redirect = true) {
    $todo = [];
    foreach ((array) $urls as $u) {
        if (!$u) continue;
        $k = nps_fetch_key($u, $redirect);
        if (!isset($todo[$k]) && !array_key_exists($k, $GLOBALS['nps_fetch_cache'])) $todo[$k] = $u;
    }
    foreach (array_chunk($todo, 10, true) as $chunk) {
        $reqs = [];
        foreach ($chunk as $u) $reqs[] = ['method' => 'GET', 'url' => $u, 'redirect' => $redirect, 'timeout' => 25];
        $rs = nps_http_multi($reqs);
        $i = 0;
        foreach ($chunk as $k => $u) {
            $r = $rs[$i++] ?? null;
            if ($r && $r['code'] && $r['code'] < 400) $GLOBALS['nps_fetch_cache'][$k] = $r;
        }
    }
}

function nps_clear_prefetch() { $GLOBALS['nps_fetch_cache'] = []; }

function nps_host($url) {
    return preg_match('#^https?://([^/?\#:]+)#i', (string) $url, $m) ? strtolower($m[1]) : '';
}

function nps_is_official($url, $domains) {
    $h = nps_host($url);
    foreach ((array) $domains as $d) {
        $d = ltrim(strtolower((string) $d), '.');
        if ($d && ($h === $d || substr($h, -(strlen($d) + 1)) === '.' . $d)) return true;
    }
    return false;
}

function nps_clean_domains($list) {
    $out = [];
    foreach ((array) $list as $d) {
        $d = preg_replace(['#^https?://#', '#/.*$#', '#^www\.#'], '', strtolower(trim((string) $d)));
        if (strpos($d, '.') > 0 && !in_array($d, $out, true)) $out[] = $d;
    }
    return $out;
}

function nps_resolve_url($href, $base) {
    $href = trim(nps_decode((string) $href));
    if ($href === '' || preg_match('#^(javascript|mailto|tel|data):#i', $href)) return null;
    if (preg_match('#^https?://#i', $href)) return $href;
    if (!preg_match('#^(https?:)//([^/?\#]+)([^?\#]*)#i', $base, $m)) return null;
    if (strpos($href, '//') === 0) return $m[1] . $href;
    if ($href[0] === '/') return $m[1] . '//' . $m[2] . $href;
    if ($href[0] === '?') return $m[1] . '//' . $m[2] . $m[3] . $href;
    if ($href[0] === '#') return explode('#', $base)[0] . $href;
    $dir = preg_replace('#[^/]*$#', '', $m[3]) ?: '/';
    $parts = explode('/', $dir . $href);
    $out = [];
    foreach ($parts as $i => $p) {
        if ($p === '..') { if (count($out) > 1) array_pop($out); }
        elseif ($p !== '.' || $i === count($parts) - 1) $out[] = $p === '.' ? '' : $p;
    }
    return $m[1] . '//' . $m[2] . implode('/', $out);
}

function nps_decode($s) {
    return html_entity_decode((string) $s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function nps_strip($s) {
    return trim(preg_replace('/\s+/u', ' ', nps_decode(preg_replace('/<[^>]*>/', ' ', (string) $s))));
}

function nps_attrs($tag) {
    $out = [];
    preg_match_all('/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))/', $tag, $ms, PREG_SET_ORDER);
    foreach ($ms as $m) $out[strtolower($m[1])] = isset($m[5]) && $m[5] !== '' ? $m[5] : (isset($m[4]) && $m[4] !== '' ? $m[4] : $m[3]);
    return $out;
}

function nps_meta($html, $prop) {
    preg_match_all('/<meta\b[^>]*>/i', $html, $ms);
    foreach ($ms[0] as $tag) {
        $a = nps_attrs($tag);
        if (strtolower($a['property'] ?? $a['name'] ?? '') === $prop) return nps_decode($a['content'] ?? '');
    }
    return '';
}

function nps_jsonld_products($html) {
    $out = [];
    preg_match_all('#<script[^>]*application/ld\+json[^>]*>([\s\S]*?)</script>#i', $html, $ms);
    foreach ($ms[1] as $raw) {
        $data = json_decode($raw, true);
        if ($data === null) continue;
        $stack = [$data];
        while ($stack) {
            $d = array_pop($stack);
            if (!is_array($d)) continue;
            $t = $d['@type'] ?? null;
            if ($t === 'Product' || (is_array($t) && in_array('Product', $t, true))) $out[] = $d;
            foreach ($d as $v) if (is_array($v)) $stack[] = $v;
        }
    }
    return $out;
}

function nps_page_text($html, $max = 15000) {
    $s = preg_replace('#<(script|style|noscript|svg|nav|header|footer|iframe)\b[\s\S]*?</\1>#i', ' ', $html);
    $s = preg_replace('/<!--[\s\S]*?-->/', ' ', $s);
    $s = preg_replace(['/<h[1-6][^>]*>/i', '/<li[^>]*>/i', '#</(td|th)>#i', '#<(br|/p|/div|/tr|/h[1-6]|/li|/dt|/dd|/section)[^>]*>#i', '/<[^>]*>/'],
        ["\n## ", "\n- ", ' | ', "\n", ' '], $s);
    $out = [];
    foreach (explode("\n", nps_decode($s)) as $l) {
        $l = trim(preg_replace('/\s+/u', ' ', $l));
        if ($l === '' || $l === '-' || $l === '##' || $l === '|') continue;
        if (end($out) !== $l) $out[] = $l;
    }
    return mb_substr(implode("\n", $out), 0, $max);
}

// A thumbnail / resized URL -> the original, full-size image URL.
function nps_canonical_image($url) {
    if (!preg_match('#\.(jpe?g|png|webp)(/|$)#i', preg_split('/[?#]/', $url)[0])) return $url;
    $u = preg_replace('/-\d{2,4}x\d{2,4}(?=\.(jpe?g|png|webp)(\?|$))/i', '', $url);
    $u = preg_replace('/_(\d{2,4}x\d{0,4}|\d{0,4}x\d{2,4}|pico|icon|thumb|small|compact|medium|large|grande)(?=\.(jpe?g|png|webp))/i', '', $u);
    $u = preg_replace('#(/media/[^/?\#]+\.(jpe?g|png|webp))/v1/.*$#i', '$1', $u);
    $u = preg_replace('/([?&])format=\d+w/i', '${1}format=2500w', $u);
    $u = preg_replace('/([?&])(width|height|w|h|resize|fit|crop|quality|q)=[^&#]*/i', '$1', $u);
    $u = preg_replace(['/[?&]+(#|$)/', '/\?&+/', '/&&+/'], ['$1', '?', '&'], $u);
    return $u;
}

function nps_image_key($url) {
    if (!preg_match('#\.(jpe?g|png|webp)(/|$)#i', preg_split('/[?#]/', $url)[0])) return $url;
    $parts = explode('/', preg_split('/[?#]/', nps_canonical_image($url))[0]);
    $name = strtolower(end($parts));
    return preg_replace(['/\.(jpe?g|png|webp)$/', '/(-scaled|@\dx|-e\d{10,})$/'], '', $name);
}

function nps_largest_from_srcset($srcset) {
    $best = null; $bestW = -1;
    if (preg_match_all('/(\S+?)\s+(\d+(?:\.\d+)?)([wx])\s*(?:,|$)/i', trim((string) $srcset), $ms, PREG_SET_ORDER)) {
        foreach ($ms as $m) {
            $w = (float) $m[2] * (strtolower($m[3]) === 'x' ? 1000 : 1);
            if ($w > $bestW) { $best = ltrim($m[1], ','); $bestW = $w; }
        }
        return $best;
    }
    $first = trim(explode(',', (string) $srcset)[0]);
    return $first !== '' ? preg_split('/\s+/', $first)[0] : null;
}

function nps_classify_pdf($url, $label) {
    $text = str_replace('_', ' ', strtolower($label . ' ' . rawurldecode($url)));
    foreach (NPS_MANUAL_WORDS as $w) if (strpos($text, $w) !== false) return 'manual';
    foreach (NPS_BROCHURE_WORDS as $w) if (strpos($text, $w) !== false) return 'brochure';
    return 'document';
}

function nps_parse_page($html, $url) {
    $page = ['url' => $url, 'title' => '', 'text' => nps_page_text($html), 'images' => [], 'pdfs' => [], 'videos' => [], 'links' => []];
    $ld = nps_jsonld_products($html);
    $ldName = '';
    if ($ld) $ldName = is_string($ld[0]['name'] ?? null) ? $ld[0]['name'] : ($ld[0]['name']['@value'] ?? '');
    preg_match('#<h1\b[^>]*>([\s\S]*?)</h1>#i', $html, $h1);
    preg_match('#<title>([\s\S]*?)</title>#i', $html, $title);
    $page['title'] = nps_strip($ldName) ?: (isset($h1[1]) ? nps_strip($h1[1]) : '') ?: nps_meta($html, 'og:title') ?: nps_strip($title[1] ?? '');
    $desc = [];
    foreach ($ld as $d) if (is_string($d['description'] ?? null)) $desc[] = nps_strip($d['description']);
    if (nps_meta($html, 'og:description')) $desc[] = nps_meta($html, 'og:description');
    if ($desc) $page['text'] = implode("\n", $desc) . "\n\n" . $page['text'];

    // Several sizes of the same photo are merged, keeping the biggest source.
    $rank = ['link' => 4, 'zoom' => 4, 'json-ld' => 3, 'og:image' => 3, 'srcset' => 2, 'img' => 1];
    $byKey = [];
    $add = function ($src, $alt, $source, $cls = '') use (&$byKey, &$page, $url, $rank) {
        $src = nps_resolve_url($src, $url);
        if (!$src) return;
        if (preg_match('#/_next/image\?(?:.*&)?url=([^&]+)#', $src, $nm)) { $src = nps_resolve_url(rawurldecode($nm[1]), $url); if (!$src) return; }
        $path = strtolower(explode('?', $src)[0]);
        if (preg_match(NPS_SKIP_IMG, $path) || preg_match('/\.(svg|gif)$/', $path)) return;
        $canon = nps_canonical_image($src);
        $key = nps_image_key($src);
        if (isset($byKey[$key])) {
            $i = $byKey[$key];
            $have = &$page['images'][$i];
            if (($rank[$source] ?? 0) > ($rank[$have['source']] ?? 0)) {
                if ($have['url'] !== $canon && !$have['fallback']) $have['fallback'] = $have['url'];
                $have['url'] = $canon;
                $have['source'] = $source;
            }
            if (!$have['alt'] && $alt) $have['alt'] = mb_substr(nps_strip($alt), 0, 120);
            unset($have);
            return;
        }
        $byKey[$key] = count($page['images']);
        $page['images'][] = ['url' => $canon, 'fallback' => $canon !== $src ? $src : '', 'alt' => mb_substr(nps_strip($alt), 0, 120), 'source' => $source, 'where' => $cls];
    };
    foreach ($ld as $d) {
        $imgs = $d['image'] ?? [];
        if (!is_array($imgs) || isset($imgs['url'])) $imgs = [$imgs];
        foreach ($imgs as $i) $add(is_string($i) ? $i : ($i['url'] ?? ''), '', 'json-ld');
    }
    if (nps_meta($html, 'og:image')) $add(nps_meta($html, 'og:image'), '', 'og:image');
    preg_match_all('/<img\b[^>]*>/i', $html, $ms);
    foreach ($ms[0] as $tag) {
        $a = nps_attrs($tag);
        $zoom = $a['data-large_image'] ?? $a['data-zoom-image'] ?? $a['data-full'] ?? $a['data-full-url'] ?? $a['data-highres'] ?? $a['data-orig-file'] ?? '';
        $set = nps_largest_from_srcset($a['data-srcset'] ?? $a['srcset'] ?? '');
        $src = $a['data-src'] ?? $a['data-lazy-src'] ?? $a['data-original'] ?? $a['src'] ?? '';
        $cls = mb_substr($a['class'] ?? '', 0, 60);
        if ($src && strpos($src, 'data:') !== 0) $add($src, $a['alt'] ?? '', 'img', $cls);
        if ($set) $add($set, $a['alt'] ?? '', 'srcset', $cls);
        if ($zoom) $add($zoom, $a['alt'] ?? '', 'zoom', $cls);
    }
    preg_match_all('#<a\b([^>]*)>([\s\S]*?)</a>#i', $html, $ms, PREG_SET_ORDER);
    $seen = [];
    foreach ($ms as $m) {
        $at = nps_attrs('<a ' . $m[1] . '>');
        $href = nps_resolve_url($at['href'] ?? '', $url);
        if (!$href) continue;
        $label = nps_strip($m[2]) ?: ($at['title'] ?? '');
        if (preg_match('/\.pdf(\?|#|$)/i', $href)) {
            $dup = false;
            foreach ($page['pdfs'] as $p) if ($p['url'] === $href) $dup = true;
            if (!$dup) $page['pdfs'][] = ['url' => $href, 'label' => mb_substr($label, 0, 150), 'kind' => nps_classify_pdf($href, $label)];
        } elseif (preg_match('/\.(jpe?g|png|webp)(\?|$)/i', $href)) {
            $add($href, $label, 'link');
        } elseif (!isset($seen[$href]) && preg_match('#^https?:#i', $href)) {
            $seen[$href] = true;
            $page['links'][] = ['url' => explode('#', $href)[0], 'text' => mb_substr($label, 0, 120)];
        }
    }
    preg_match_all('#(?:youtube(?:-nocookie)?\.com/(?:embed/|watch\?v=|v/|shorts/)|youtu\.be/)([A-Za-z0-9_-]{11})#', $html, $ms, PREG_OFFSET_CAPTURE);
    $seenVid = [];
    foreach ($ms[1] as $m) {
        $id = $m[0];
        if (isset($seenVid[$id]) || $id === 'videoseries') continue;
        $seenVid[$id] = true;
        $around = substr($html, max(0, $m[1] - 300), 600);
        $t = preg_match('/title=["\']([^"\']{3,120})["\']/i', $around, $tm) ? nps_decode($tm[1]) : '';
        $page['videos'][] = ['url' => 'https://www.youtube.com/watch?v=' . $id, 'title' => $t];
    }
    return $page;
}

// Follows redirects itself so relative links are resolved against the page's real address.
function nps_fetch_page($url) {
    $r = null;
    for ($hop = 0; $hop < 6; $hop++) {
        $r = nps_fetch($url, false);
        if (!$r) return null;
        $loc = $r['headers']['location'] ?? '';
        if ($r['code'] >= 300 && $r['code'] < 400 && $loc) { $url = nps_resolve_url($loc, $url); if (!$url) return null; continue; }
        break;
    }
    $type = $r['headers']['content-type'] ?? '';
    if ($type && !preg_match('/html|xml/i', $type)) return null;
    $html = $r['body'];
    if (!preg_match('//u', $html)) $html = mb_convert_encoding($html, 'UTF-8', 'Windows-1252');
    $base = preg_match('#<base\b[^>]*href=["\']([^"\']+)["\']#i', $html, $bm) ? $bm[1] : '';
    $page = nps_parse_page($html, $base ? (nps_resolve_url($base, $url) ?: $url) : $url);
    $page['url'] = $url;
    return $page;
}
