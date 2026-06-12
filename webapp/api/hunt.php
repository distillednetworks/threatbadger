<?php
// ============================================================
//  ThreatBadger — api/hunt.php
//  Searches a log-focused Elasticsearch cluster for indicator
//  matches across standard ECS fields.
//  Place this file at: webapp/api/hunt.php
// ============================================================

require_once __DIR__ . '/../includes/functions.php';

ts_session_start();
header('Content-Type: application/json');

if (!auth_check())                         json_error('Not authenticated', 401);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_error('POST required', 405);
if (!rate_limit_check('lookup', RATE_LIMIT_LOOKUPS, 60)) json_error('Rate limit exceeded', 429);

$body      = json_decode(file_get_contents('php://input'), true);
$indicator = trim($body['indicator'] ?? '');
$index     = trim($body['index']     ?? '') ?: (defined('HUNT_ELASTIC_INDEX') ? HUNT_ELASTIC_INDEX : 'logs-*');
$from      = max(0, (int)($body['from'] ?? 0));
$size      = min(100, max(1, (int)($body['size'] ?? 25)));
$time_from = trim($body['time_from'] ?? 'now-30d');   // ES date math or ISO 8601
$time_to   = trim($body['time_to']   ?? 'now');

if (empty($indicator)) json_error('indicator is required');

$type = detect_type($indicator);
if (!$type) json_error('Could not detect indicator type. Supported: IPv4, IPv6, Domain, Email, MD5, SHA-1, SHA-256');

// ─── Validate hunt config ─────────────────────────────────────
$hunt_url = defined('HUNT_ELASTIC_URL') ? HUNT_ELASTIC_URL : '';
$hunt_key = defined('HUNT_ELASTIC_API_KEY') ? HUNT_ELASTIC_API_KEY : '';
if (empty($hunt_url) || empty($hunt_key)) {
    json_error('Hunt Elasticsearch is not configured. Add HUNT_ELASTIC_URL and HUNT_ELASTIC_API_KEY to config.php');
}

// ─── Build ECS-aware query per indicator type ─────────────────
// Targets the standard ECS fields where each value type appears
// in log data (network events, DNS, HTTP, file events, etc.)
function build_hunt_query(string $indicator, string $type, int $from, int $size, string $time_from, string $time_to): array {
    $should = [];

    switch ($type) {

        case 'IPv4 Address':
        case 'IPv6 Address':
            $should[] = ['term' => ['source.ip'              => $indicator]];
            $should[] = ['term' => ['destination.ip'         => $indicator]];
            $should[] = ['term' => ['client.ip'              => $indicator]];
            $should[] = ['term' => ['server.ip'              => $indicator]];
            $should[] = ['term' => ['host.ip'                => $indicator]];
            $should[] = ['term' => ['dns.resolved_ip'        => $indicator]];
            $should[] = ['term' => ['dns.answers.data'       => $indicator]];
            $should[] = ['term' => ['source.nat.ip'          => $indicator]];
            $should[] = ['term' => ['destination.nat.ip'     => $indicator]];
            $should[] = ['term' => ['related.ip'             => $indicator]];
            $should[] = ['term' => ['ip'                     => $indicator]];
            $should[] = ['term' => ['src_ip'                 => $indicator]];
            $should[] = ['term' => ['dst_ip'                 => $indicator]];
            $should[] = ['term' => ['remote_ip'              => $indicator]];
            break;

        case 'Domain':
            $wc = '*' . $indicator . '*';
            $should[] = ['term'     => ['dns.question.name'                       => $indicator]];
            $should[] = ['wildcard' => ['dns.question.name'                       => ['value' => $wc]]];
            $should[] = ['term'     => ['url.domain'                              => $indicator]];
            $should[] = ['wildcard' => ['url.full.text'                           => ['value' => $wc]]];
            $should[] = ['term'     => ['http.request.referrer'                   => $indicator]];
            $should[] = ['term'     => ['tls.server.x509.subject.common_name'     => $indicator]];
            $should[] = ['wildcard' => ['tls.server.x509.alternative_names'       => ['value' => $wc]]];
            $should[] = ['term'     => ['host.hostname'                           => $indicator]];
            $should[] = ['term'     => ['host.name'                               => $indicator]];
            $should[] = ['wildcard' => ['email.from.address'                      => ['value' => $wc]]];
            $should[] = ['wildcard' => ['email.to.address'                        => ['value' => $wc]]];
            $should[] = ['term'     => ['related.hosts'                           => $indicator]];
            $should[] = ['wildcard' => ['domain'                                  => ['value' => $wc]]];
            $should[] = ['wildcard' => ['destination.domain'                      => ['value' => $wc]]];
            break;

        case 'Email Address':
            $should[] = ['term' => ['email.from.address'       => $indicator]];
            $should[] = ['term' => ['email.to.address'         => $indicator]];
            $should[] = ['term' => ['email.reply_to.address'   => $indicator]];
            $should[] = ['term' => ['email.sender.address'     => $indicator]];
            $should[] = ['term' => ['email.cc.address'         => $indicator]];
            $should[] = ['term' => ['email.bcc.address'        => $indicator]];
            $should[] = ['term' => ['user.email'               => $indicator]];
            $should[] = ['term' => ['user.target.email'        => $indicator]];
            $should[] = ['term' => ['source.user.email'        => $indicator]];
            $should[] = ['term' => ['destination.user.email'   => $indicator]];
            $should[] = ['term' => ['related.user'             => $indicator]];
            break;

        case 'MD5 Hash':
        case 'SHA-1 Hash':
        case 'SHA-256 Hash':
            $field = $type === 'MD5 Hash' ? 'md5' : ($type === 'SHA-1 Hash' ? 'sha1' : 'sha256');
            $should[] = ['term' => ["file.hash.$field"                            => $indicator]];
            $should[] = ['term' => ["process.executable.hash.$field"              => $indicator]];
            $should[] = ['term' => ["threat.indicator.file.hash.$field"           => $indicator]];
            $should[] = ['term' => ["threat.enrichments.indicator.file.hash.$field" => $indicator]];
            $should[] = ['term' => [$field                                        => $indicator]];
            $should[] = ['term' => ["hash.$field"                                 => $indicator]];
            $should[] = ['term' => ["file_hash"                                   => $indicator]];
            $should[] = ['term' => ["process.hash.$field"                         => $indicator]];
            break;
    }

    return [
        'query' => [
            'bool' => [
                'must' => [
                    // Time range — always applied via @timestamp
                    ['range' => ['@timestamp' => ['gte' => $time_from, 'lte' => $time_to]]],
                ],
                'should'               => $should,
                'minimum_should_match' => 1,
            ],
        ],
        'size'  => $size,
        'from'  => $from,
        'sort'  => [['@timestamp' => ['order' => 'desc']]],
        '_source' => true,
        'highlight' => [
            'fields'              => ['*' => new stdClass()],
            'require_field_match' => false,
            'number_of_fragments' => 0,
        ],
        'timeout' => '100s', // Have ES return what it has after this time
    ];
}

$query = build_hunt_query($indicator, $type, $from, $size, $time_from, $time_to);

// ─── Execute search ───────────────────────────────────────────
$endpoint = rtrim($hunt_url, '/') . '/' . rawurlencode($index) . '/_search';
$res = http_post(
    $endpoint,
    $query,
    ['Authorization' => 'ApiKey ' . $hunt_key, 'Content-Type' => 'application/json'],
    false,
    120  // 2-minute timeout for potentially large log searches
);

if (!$res['ok']) {
    json_error('Elasticsearch error: ' . ($res['error'] ?? "HTTP {$res['status']}"), $res['status'] ?: 500);
}

$raw_hits = $res['data']['hits']['hits']        ?? [];
$total    = $res['data']['hits']['total']['value'] ?? count($raw_hits);
$took_ms  = $res['data']['took']                 ?? null;

// ─── Normalise hits ───────────────────────────────────────────
$hunt_kibana = defined('HUNT_KIBANA_URL') ? HUNT_KIBANA_URL : '';
$hits = [];
foreach ($raw_hits as $h) {
    $src = $h['_source'] ?? [];

    // Build a readable one-line summary
    $cats = is_array($src['event']['category'] ?? null) ? implode(', ', $src['event']['category']) : ($src['event']['category'] ?? '');
    $action = $src['event']['action'] ?? '';
    $kind   = is_array($src['event']['type'] ?? null) ? implode(', ', $src['event']['type']) : ($src['event']['type'] ?? '');
    $summary_parts = array_filter([$cats, $action, $kind]);
    $summary = implode(' / ', $summary_parts) ?: ($src['message'] ?? '');

    $kibana_link = '';
    if ($hunt_kibana) {
        $kibana_link = rtrim($hunt_kibana, '/') . '/app/discover#/doc/security-solution-default/'
                     . urlencode($h['_index']) . '?id=' . urlencode($h['_id']);
    }

    $hits[] = [
        '_index'      => $h['_index'],
        '_id'         => $h['_id'],
        'timestamp'   => $src['@timestamp'] ?? null,
        'summary'     => $summary,
        'source'      => $src,
        'highlight'   => $h['highlight'] ?? [],
        'kibana_link' => $kibana_link,
    ];
}

echo json_encode([
    'indicator' => $indicator,
    'type'      => $type,
    'index'     => $index,
    'time_from' => $time_from,
    'time_to'   => $time_to,
    'total'     => $total,
    'from'      => $from,
    'size'      => $size,
    'took_ms'   => $took_ms,
    'hits'      => $hits,
]);
