<?php
// HTTP: single requests through wp_remote_*, several at the same time through Requests::request_multiple.
// Both can be replaced in tests (pre_http_request / the nps_http_multi filter).

if (!defined('ABSPATH')) exit;

define('NPS_UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36');

// Spaces, Hebrew letters etc. must be percent-encoded (already-encoded %XX stays as is).
function nps_encode_url($url) {
    return preg_replace_callback('/[^\x21-\x7e]+/', function ($m) { return rawurlencode($m[0]); }, (string) $url);
}

// Returns ['code' => int, 'body' => string, 'headers' => array (lower-case), 'error' => string].
function nps_http($method, $url, $opts = []) {
    $args = [
        'method' => strtoupper($method),
        'timeout' => $opts['timeout'] ?? 25,
        'redirection' => array_key_exists('redirect', $opts) && !$opts['redirect'] ? 0 : 5,
        'headers' => array_merge(['User-Agent' => NPS_UA, 'Accept-Language' => 'en-US,en;q=0.9'], $opts['headers'] ?? []),
        'limit_response_size' => $opts['limit'] ?? 60 * 1024 * 1024,
        'reject_unsafe_urls' => empty($opts['trusted']),
    ];
    if (isset($opts['body'])) $args['body'] = $opts['body'];
    $r = wp_remote_request(nps_encode_url($url), $args);
    if (is_wp_error($r)) return ['code' => 0, 'body' => '', 'headers' => [], 'error' => $r->get_error_message()];
    $headers = [];
    foreach ((array) wp_remote_retrieve_headers($r) as $k => $v) $headers[strtolower($k)] = is_array($v) ? end($v) : $v;
    return ['code' => (int) wp_remote_retrieve_response_code($r), 'body' => (string) wp_remote_retrieve_body($r), 'headers' => $headers, 'error' => ''];
}

// Several requests at the same time: [['method','url','headers','body','timeout'], ...] -> responses in the same order.
function nps_http_multi($reqs) {
    $short = apply_filters('nps_http_multi', null, $reqs);
    if ($short !== null) return $short;
    if (!$reqs) return [];
    $class = class_exists('\WpOrg\Requests\Requests') ? '\WpOrg\Requests\Requests' : '\Requests';
    $list = [];
    foreach ($reqs as $i => $q) {
        $list[$i] = [
            'url' => nps_encode_url($q['url']),
            'type' => strtoupper($q['method'] ?? 'GET'),
            'headers' => array_merge(['User-Agent' => NPS_UA], $q['headers'] ?? []),
            'data' => $q['body'] ?? [],
            'options' => ['timeout' => $q['timeout'] ?? 25, 'connect_timeout' => 15, 'follow_redirects' => !isset($q['redirect']) || $q['redirect'], 'redirects' => 5],
        ];
    }
    $out = [];
    try {
        $rs = $class::request_multiple($list, ['timeout' => 25]);
    } catch (\Throwable $e) {
        foreach ($reqs as $i => $q) $out[$i] = ['code' => 0, 'body' => '', 'headers' => [], 'error' => $e->getMessage()];
        return $out;
    }
    foreach ($reqs as $i => $q) {
        $r = $rs[$i] ?? null;
        if (!$r || $r instanceof \Throwable || !isset($r->status_code)) {
            $out[$i] = ['code' => 0, 'body' => '', 'headers' => [], 'error' => $r instanceof \Throwable ? $r->getMessage() : 'no response'];
            continue;
        }
        $headers = [];
        foreach ($r->headers as $k => $v) $headers[strtolower($k)] = $v;
        $out[$i] = ['code' => (int) $r->status_code, 'body' => (string) $r->body, 'headers' => $headers, 'error' => ''];
    }
    return $out;
}
