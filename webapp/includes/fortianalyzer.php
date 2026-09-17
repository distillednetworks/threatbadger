<?php
// ============================================================
//  ThreatBadger — includes/fortianalyzer.php
//  FortiAnalyzer JSON-RPC integration used by the Hunt page.
//
//  Auth:   API key (preferred, Authorization: Bearer) or
//          session-based username/password login.
//  Search: two-step async LogView workflow —
//          1) "add"  /logview/adom/{adom}/logsearch   -> tid
//          2) "get"  /logview/adom/{adom}/logsearch/{tid} -> logs (polled)
//
//  IPv4/IPv6 indicators  -> Traffic logs (source or destination IP)
//                           + VPN event logs (remote IP or assigned tunnel IP)
//  Domain indicators     -> DNS logs + Web Filter logs
// ============================================================

require_once __DIR__ . '/functions.php';

// ─── Config ──────────────────────────────────────────────────
function faz_config(): array {
    return [
        'url'        => defined('FORTIANALYZER_URL')        ? trim(FORTIANALYZER_URL)   : '',
        'adom'       => defined('FORTIANALYZER_ADOM')        ? trim(FORTIANALYZER_ADOM)  : 'root',
        'api_key'    => defined('FORTIANALYZER_API_KEY')     ? trim(FORTIANALYZER_API_KEY) : '',
        'username'   => defined('FORTIANALYZER_USERNAME')    ? trim(FORTIANALYZER_USERNAME) : '',
        'password'   => defined('FORTIANALYZER_PASSWORD')    ? FORTIANALYZER_PASSWORD    : '',
        'device'     => defined('FORTIANALYZER_DEVICE')      ? trim(FORTIANALYZER_DEVICE) : '',
        'verify_ssl' => defined('FORTIANALYZER_VERIFY_SSL')  ? (bool)FORTIANALYZER_VERIFY_SSL : true,
    ];
}

function faz_is_configured(array $cfg): bool {
    if (empty($cfg['url']) || empty($cfg['adom'])) return false;
    return !empty($cfg['api_key']) || (!empty($cfg['username']) && !empty($cfg['password']));
}

/**
 * Sanitize a user-supplied ADOM or device name: strip control/whitespace
 * chars that have no business in these identifiers, and cap length. This
 * runs before the value is used in a JSON-RPC URL path segment or payload
 * field — both of which are safely encoded downstream (rawurlencode /
 * json_encode) — so this is a defense-in-depth allow-list, not the sole
 * protection against injection.
 */
function faz_sanitize_field(string $value, int $maxLen): string {
    $value = preg_replace('/[^A-Za-z0-9 ._\-]/', '', $value) ?? '';
    return substr(trim($value), 0, $maxLen);
}

// ─── Filter string safety ──────────────────────────────────────
/**
 * FortiAnalyzer's filter language isn't a parameterised query API, so the
 * indicator value has to be assembled into a filter string. It is always
 * type-checked upstream (detect_type() in functions.php only accepts well
 * formed IPv4/IPv6/domain values) — this is a defense-in-depth layer that
 * strips characters which could otherwise break out of the quoted string.
 */
function faz_filter_escape(string $value): string {
    return str_replace(['"', '\\', "\r", "\n"], '', $value);
}

/**
 * Build the FortiAnalyzer log searches required for an indicator.
 * Returns a list of ['logtype' => ..., 'filter' => ..., 'submit_as'? => ...].
 * 'submit_as' overrides the API logtype sent to FortiAnalyzer when the
 * label used for display/normalisation differs from FortiAnalyzer's own
 * logtype name (VPN events are stored under the generic 'event' logtype).
 */
function build_fortianalyzer_hunt_queries(string $indicator, string $type): array {
    $safe = faz_filter_escape($indicator);

    if ($type === 'IPv4 Address' || $type === 'IPv6 Address') {
        return [
            ['logtype' => 'traffic', 'filter' => "srcip==\"$safe\" or dstip==\"$safe\""],
            // VPN connection events (SSL-VPN/IPsec) live under the 'event' logtype.
            // remip is the client's real-world source IP; assignip is the tunnel
            // IP handed out to it — both are worth matching against the indicator.
            ['logtype' => 'vpn', 'submit_as' => 'event', 'filter' => "subtype==vpn and (remip==\"$safe\" or assignip==\"$safe\")"],
        ];
    }

    if ($type === 'Domain') {
        return [
            ['logtype' => 'dns',       'filter' => "qname contains \"$safe\""],
            ['logtype' => 'webfilter', 'filter' => "hostname contains \"$safe\""],
        ];
    }

    return [];
}

// ─── Time range ─────────────────────────────────────────────
/**
 * Convert the Hunt page's time inputs — either Elasticsearch-style relative
 * shorthand ("now-30d" / "now") or ISO 8601 from the absolute-mode picker —
 * into "Y-m-d H:i:s" strings, which is what FortiAnalyzer's time-range
 * object expects.
 */
function faz_resolve_time_range(string $from, string $to): array {
    $now = new DateTime('now');

    $resolve = function (string $v) use ($now): DateTime {
        if ($v === '' || $v === 'now') return clone $now;
        if (preg_match('/^now-(\d+)([mhdwM])$/', $v, $m)) {
            $n = (int)$m[1];
            $dt = clone $now;
            switch ($m[2]) {
                case 'm': $dt->modify("-{$n} minutes"); break;
                case 'h': $dt->modify("-{$n} hours");   break;
                case 'd': $dt->modify("-{$n} days");    break;
                case 'w': $dt->modify("-{$n} weeks");   break;
                case 'M': $dt->modify("-{$n} months");  break;
            }
            return $dt;
        }
        try {
            return new DateTime($v);
        } catch (Exception $e) {
            return clone $now;
        }
    };

    $fromDt = $resolve($from);
    $toDt   = $resolve($to);
    if ($fromDt > $toDt) { [$fromDt, $toDt] = [$toDt, $fromDt]; }

    return [$fromDt->format('Y-m-d H:i:s'), $toDt->format('Y-m-d H:i:s')];
}

// ─── JSON-RPC transport ────────────────────────────────────────
/**
 * Raw JSON-RPC call — returns the full decoded HTTP response.
 *
 * $flatten controls the shape of the params object, since FortiAnalyzer's
 * own modules disagree on this: session/config endpoints (e.g. login) take
 * their arguments nested under "data", while the LogView search endpoints
 * (per Fortinet's own tested support article) expect fields flattened as
 * direct siblings of "url", plus an explicit "apiver": 3.
 */
function faz_raw_call(string $method, string $url, array $fields, array $cfg, ?string $session, bool $flatten = false): array {
    // Some FortiAnalyzer builds key off "url", others off "uri" — send both.
    $params = ['url' => $url, 'uri' => $url];
    if ($flatten) {
        $params['apiver'] = 3;
        $params = array_merge($params, $fields);
    } elseif (!empty($fields)) {
        $params['data'] = $fields;
    }

    $payload = [
        'method'  => $method,
        'params'  => [$params],
        'session' => $session,
        'id'      => 1,
        'jsonrpc' => '2.0',
    ];

    $headers = ['Content-Type' => 'application/json'];
    if (!empty($cfg['api_key'])) {
        $headers['Authorization'] = 'Bearer ' . $cfg['api_key'];
    }

    return http_post(
        rtrim($cfg['url'], '/') . '/jsonrpc',
        $payload,
        $headers,
        $cfg['verify_ssl'] ?? true,
        30
    );
}

/**
 * JSON-RPC call that unwraps FortiAnalyzer's response and surfaces its own
 * error codes. Handles both response shapes seen across FortiAnalyzer
 * versions/endpoints: "result" as a single-element array with status/data
 * inside each element (older/generic), and "result" as a single object with
 * "status" nested directly inside it (LogView with apiver 3).
 */
function faz_call(string $method, string $url, array $fields, array $cfg, ?string $session, bool $flatten = false): array {
    $res = faz_raw_call($method, $url, $fields, $cfg, $session, $flatten);

    if (!is_array($res['data'] ?? null)) {
        return ['ok' => false, 'error' => $res['error'] ?? 'FortiAnalyzer connection failed'];
    }

    $body = $res['data'];

    if (isset($body['error'])) {
        return ['ok' => false, 'error' => 'FortiAnalyzer: ' . ($body['error']['message'] ?? 'unknown error')];
    }

    $result = $body['result'] ?? null;
    if ($result === null) {
        return ['ok' => false, 'error' => 'Unexpected FortiAnalyzer response'];
    }

    $isList = function_exists('array_is_list')
        ? array_is_list($result)
        : ($result === [] || array_keys($result) === range(0, count($result) - 1));
    $entry  = $isList ? ($result[0] ?? null) : $result;
    if ($entry === null) {
        return ['ok' => false, 'error' => 'Unexpected FortiAnalyzer response'];
    }

    $status = $entry['status'] ?? null;
    if (is_array($status) && ($status['code'] ?? 0) !== 0) {
        return ['ok' => false, 'error' => 'FortiAnalyzer: ' . ($status['message'] ?? ('error code ' . $status['code']))];
    }

    // Older shape nests the payload under "data"; the flattened LogView
    // shape returns the payload directly as the result object.
    $data = $isList ? ($entry['data'] ?? $entry) : $entry;

    return ['ok' => true, 'data' => $data, 'raw' => $body];
}

// ─── Session lifecycle ──────────────────────────────────────
function faz_login(array $cfg): array {
    if (empty($cfg['username']) || empty($cfg['password'])) {
        return ['ok' => false, 'error' => 'FortiAnalyzer session login is not configured'];
    }
    $r = faz_call('exec', '/sys/login/user', ['user' => $cfg['username'], 'passwd' => $cfg['password']], $cfg, null);
    if (!$r['ok']) return $r;

    $session = $r['raw']['session'] ?? null;
    if (empty($session)) {
        return ['ok' => false, 'error' => 'FortiAnalyzer login did not return a session'];
    }
    return ['ok' => true, 'session' => $session];
}

function faz_logout(array $cfg, ?string $session): void {
    if (!$session) return;
    // Best-effort cleanup — a failed logout must never surface to the user.
    faz_call('exec', '/sys/logout', [], $cfg, $session);
}

/** Establish auth context: API key needs no session; otherwise log in. */
function faz_get_session(array $cfg): array {
    if (!empty($cfg['api_key'])) {
        return ['ok' => true, 'session' => null, 'owns_session' => false];
    }
    $login = faz_login($cfg);
    if (!$login['ok']) return $login;
    return ['ok' => true, 'session' => $login['session'], 'owns_session' => true];
}

// ─── Log search (two-step async) ───────────────────────────────
function faz_search_logs(array $cfg, ?string $session, string $logtype, string $filter, string $time_from, string $time_to, int $limit, int $offset, ?string $apiLogtype = null): array {
    $data = [
        'logtype'        => $apiLogtype ?? $logtype,
        'filter'         => $filter,
        'time-range'     => ['start' => $time_from, 'end' => $time_to],
        'time-order'     => 'desc',
        'case-sensitive' => false,
    ];
    // FortiAnalyzer's LogView search expects an explicit "device" entry —
    // omitting it entirely triggers "Device type is unknown" on some builds.
    // "All_Devices" is FortiAnalyzer's own reserved devid for "search every
    // managed device"; a configured device name overrides it.
    $data['device'] = !empty($cfg['device'])
        ? [['devname' => $cfg['device']]]
        : [['devid' => 'All_Devices']];

    $adomPath = '/logview/adom/' . rawurlencode($cfg['adom']);

    $submit = faz_call('add', $adomPath . '/logsearch', $data, $cfg, $session, true);
    if (!$submit['ok']) return $submit;

    $tid = $submit['data']['tid'] ?? null;
    if (!$tid) {
        return ['ok' => false, 'error' => 'FortiAnalyzer did not return a search task id'];
    }

    // Poll until complete. Bounded so a stalled/unreachable task can't hang
    // this request indefinitely (~20s max).
    $polled = null;
    for ($i = 0; $i < 20; $i++) {
        $poll = faz_call('get', $adomPath . "/logsearch/$tid", ['limit' => $limit, 'offset' => $offset], $cfg, $session, true);
        if (!$poll['ok']) return $poll;
        $polled = $poll['data'];

        $percentage = (int)($polled['percentage'] ?? 0);
        $statusVal  = $polled['status'] ?? null; // string ("running"/"done") on some builds; status object already consumed by faz_call on others
        $done = $percentage >= 100 && (!is_string($statusVal) || $statusVal === 'done');
        if ($done) break;

        usleep(1000000); // 1s
    }

    $finalPercentage = (int)($polled['percentage'] ?? 0);
    if (!$polled || $finalPercentage < 100) {
        return ['ok' => false, 'error' => "FortiAnalyzer $logtype search timed out waiting for results"];
    }

    $logs  = $polled['logs'] ?? $polled['data'] ?? [];
    $total = $polled['total_lines'] ?? $polled['total-count'] ?? count($logs);

    return [
        'ok'    => true,
        'logs'  => $logs,
        'total' => (int)$total,
    ];
}

// ─── Result normalisation (map to ECS-like shape for the shared UI) ─────
function faz_normalize_hit(array $log, string $logtype): array {
    $date = (string)($log['date'] ?? '');
    $time = (string)($log['time'] ?? '');
    $ts   = ($date && $time) ? "{$date}T{$time}" : null;

    // VPN connection events carry the client's real IP in remip and the
    // tunnel IP handed out in assignip, rather than srcip/dstip.
    $srcIp = $log['srcip'] ?? ($logtype === 'vpn' ? ($log['remip']    ?? null) : null);
    $dstIp = $log['dstip'] ?? ($logtype === 'vpn' ? ($log['assignip'] ?? null) : null);

    $src = $log; // preserve every raw field for the "Other"/raw-JSON view

    $src['event'] = [
        'category' => [$logtype],
        'action'   => $log['action'] ?? ($log['cat desc'] ?? ''),
    ];
    if ($srcIp) $src['source']      = array_filter(['ip' => $srcIp, 'port' => $log['srcport'] ?? null]);
    if ($dstIp) $src['destination'] = array_filter(['ip' => $dstIp, 'port' => $log['dstport'] ?? null]);
    if (!empty($log['devname']))  $src['host'] = ['hostname' => $log['devname']];
    if (!empty($log['qname']))    $src['dns']  = ['question' => ['name' => $log['qname']]];
    if (!empty($log['hostname'])) $src['url']  = array_filter(['domain' => $log['hostname'], 'full' => $log['url'] ?? null]);
    if (!empty($log['xauthuser']) || !empty($log['user'])) {
        $src['user'] = ['name' => $log['xauthuser'] ?? $log['user']];
    }

    $summary = implode(' / ', array_filter([$logtype, $log['action'] ?? '', $log['vpntunnel'] ?? $log['service'] ?? '']));

    return [
        '_index'      => 'fortianalyzer-' . $logtype,
        '_id'         => (string)($log['sessionid'] ?? $log['xid'] ?? bin2hex(random_bytes(6))),
        'timestamp'   => $ts,
        'summary'     => $summary,
        'source'      => $src,
        'highlight'   => [],
        'kibana_link' => '',
    ];
}

// ─── Orchestration ──────────────────────────────────────────
/**
 * Run every search required for the indicator, merge results across log
 * types, sort by time (desc) and return the requested page.
 */
function fortianalyzer_hunt(string $indicator, string $type, string $time_from_raw, string $time_to_raw, int $from, int $size, string $adom_override = '', string $device_override = ''): array {
    $cfg = faz_config();

    $adom = faz_sanitize_field($adom_override, 64);
    if ($adom !== '') $cfg['adom'] = $adom;

    $device = faz_sanitize_field($device_override, 128);
    $cfg['device'] = $device; // blank = search all devices (device override always wins, incl. clearing config default)

    if (!faz_is_configured($cfg)) {
        return ['ok' => false, 'error' => 'FortiAnalyzer is not configured. Set FORTIANALYZER_URL and either FORTIANALYZER_API_KEY or FORTIANALYZER_USERNAME/PASSWORD in config.php'];
    }

    $queries = build_fortianalyzer_hunt_queries($indicator, $type);
    if (empty($queries)) {
        return ['ok' => false, 'error' => "FortiAnalyzer hunt supports IPv4, IPv6, and Domain indicators only (got: $type)"];
    }

    [$time_from, $time_to] = faz_resolve_time_range($time_from_raw, $time_to_raw);

    $sess = faz_get_session($cfg);
    if (!$sess['ok']) return $sess;
    $session = $sess['session'];

    // Fetch enough of each log type to cover this page once merged/sorted,
    // capped to bound total request time and payload size.
    $fetchLimit = max(1, min(500, $from + $size));

    $allHits = [];
    $total   = 0;
    $lastError = null;
    $anyOk   = false;

    foreach ($queries as $q) {
        $r = faz_search_logs($cfg, $session, $q['logtype'], $q['filter'], $time_from, $time_to, $fetchLimit, 0, $q['submit_as'] ?? null);
        if (!$r['ok']) { $lastError = $r['error']; continue; }
        $anyOk  = true;
        $total += $r['total'];
        foreach ($r['logs'] as $log) {
            $allHits[] = faz_normalize_hit($log, $q['logtype']);
        }
    }

    if ($sess['owns_session']) faz_logout($cfg, $session);

    if (!$anyOk) {
        return ['ok' => false, 'error' => $lastError ?: 'FortiAnalyzer search failed'];
    }

    usort($allHits, fn($a, $b) => strcmp((string)$b['timestamp'], (string)$a['timestamp']));
    $page = array_slice($allHits, $from, $size);

    return [
        'ok'      => true,
        'hits'    => $page,
        'total'   => $total,
        'logtypes'=> array_column($queries, 'logtype'),
        'adom'    => $cfg['adom'],
        'device'  => $cfg['device'],
        'time_from' => $time_from,
        'time_to'   => $time_to,
    ];
}
