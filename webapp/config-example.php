<?php
// ============================================================
//  ThreatBadger — config.php
//  Edit this file with your server settings and API keys.
//  NEVER commit this file to public source control.
// ============================================================

// ─── Application ─────────────────────────────────────────────
define('APP_NAME',    'ThreatBadger');
define('APP_VERSION', '2.1');
define('APP_ENV',     'production'); // 'development' | 'production'

// ─── Session  ────────────────────────────────────────────────
// Strong random string — run: php -r "echo bin2hex(random_bytes(32));"
define('JWT_SECRET', '');
define('SESSION_LIFETIME', 28800); // 8 hours in seconds

// ─── Auth mode ────────────────────────────────────────────────
// 'okta'  = Okta SAML SSO (recommended for production)
// 'local' = Local username/password accounts (fallback/dev only)
define('AUTH_MODE', 'local');


// ─── Users ────────────────────────────────────────────────────
// Add users here. Generate password hashes with:
//   php -r "echo password_hash('yourpassword', PASSWORD_BCRYPT);"
define('USERS', [
    'admin' => [
        'password_hash' => '',
        'role'          => 'admin',
        'display_name'  => 'Administrator',
    ],
    // Add more users here:
    // 'analyst' => [
    //     'password_hash' => '',
    //     'role'          => 'analyst',
    //     'display_name'  => 'SOC Analyst',
    // ],
]);

// ─── OKTA ────────────────────────────────────────────────────
define('OKTA_SAML', [

    // ── Your app's URLs (Service Provider) ──────────────────────
    // Base URL of this ThreatBadger installation (no trailing slash)
    'sp_base_url'         => 'https://<FDQN>',

    // These are constructed automatically — only change if you use
    // a non-standard directory structure
    'sp_acs_url'          => 'https://<FDQN>/saml/acs.php',
    'sp_entity_id'        => 'https://<FDQN>/saml/metadata.php',
    'sp_sls_url'          => 'https://<FDQN>/saml/sls.php',  // Single Logout

    // ── Okta (Identity Provider) values ─────────────────────────
    // From Okta: "View SAML setup instructions" → Identity Provider Issuer
    'idp_entity_id'       => 'http://www.okta.com/<id>',

    // From Okta: "View SAML setup instructions" → Identity Provider Single Sign-On URL
    'idp_sso_url'         => 'https://<tenant>.okta.com/app/<app>/<id>/sso/saml',

    // From Okta: "View SAML setup instructions" → Identity Provider Single Logout URL
    // (Optional — leave empty string if not configured in Okta)
    'idp_slo_url'         => 'https://<tenant>.okta.com',

    // From Okta: "View SAML setup instructions" → X.509 Certificate
    // Paste ONLY the base64 content between -----BEGIN/END CERTIFICATE-----
    'idp_x509_cert'       => '',
  
    // ── Role mapping ─────────────────────────────────────────────
    // Map Okta group names to ThreatBadger roles.
    // Users in the first matching group get that role.
    // If a user is in none of these groups, they get 'default_role' below.
    'group_role_map'      => [
        'TS-Admin'   => 'admin',
        'TS-Analyst' => 'analyst',
    ],
    'default_role'        => 'analyst',   // Role for Okta users not in any mapped group

    // ── SAML attribute names sent by Okta ────────────────────────
    // These match the Attribute Statements configured in Okta above.
    // Only change if you used different attribute names in Okta.
    'attr_email'          => 'email',
    'attr_first_name'     => 'firstName',
    'attr_last_name'      => 'lastName',
    'attr_groups'         => 'groups',

    // ── Security settings ────────────────────────────────────────
    'strict'              => true,   // Set false ONLY during initial testing
    'debug'               => false,  // Set true temporarily to diagnose SAML errors

    // Whether to sign AuthN requests sent to Okta
    // Requires SP private key + certificate configured below
    'authn_requests_signed' => false,

    // SP private key and certificate (only needed if signing AuthN requests
    // or if Okta is configured to require signed requests)
    // Generate: openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 3650 -nodes
    'sp_private_key'      => '',  // Contents of sp.key
    'sp_certificate'      => '',  // Contents of sp.crt
]);

// ───
// ─── Lookup Sources ────────────────────────────────────────────────────
// ───

// ─── MISP ────────────────────────────────────────────────────
define('MISP_URL',        '');   // e.g. https://misp.yourorg.local
define('MISP_API_KEY',    '');   // Your MISP automation key
define('MISP_VERIFY_SSL', false);

// ─── Elasticsearch - Lookups ────────────────────────────────────────────
define('ELASTIC_URL',     '');   // e.g. https://elastic.yourorg.local:9200
define('ELASTIC_API_KEY', '');   // Base64-encoded Elasticsearch API key
define('ELASTIC_INDEX',   'logs-ti*');  //Index where all Threat Data is Kept
define('KIBANA_URL', ''); // e.g. https://kibana.yourorg.local:5601
                                   // Specify the Kibana URL if applicable to get 
                                   // a link directly to events from elastic searches

// ─── VirusTotal ───────────────────────────────────────────────
define('VT_API_KEY',      '');   // 64-character VirusTotal API key

// ─── GreyNoise ────────────────────────────────────────────────
define('GREYNOISE_API_KEY', ''); // GreyNoise API key

// ─── GeoIP ────────────────────────────────────────────────────
// 'ipapi'    = ip-api.com  (free, no key needed)
// 'maxmind'  = MaxMind GeoIP2 Precision API (paid, requires key)
define('GEOIP_PROVIDER',  'ipapi');
define('MAXMIND_API_KEY', '');   // Format: AccountID:LicenseKey

// ─── HaveIBeenPwned ───────────────────────────────────────────
define('HIBP_API_KEY',      '');   // https://haveibeenpwned.com/API/Key

// ─── HackerTarget ─────────────────────────────────────────────
// Free tier works without a key (100 API calls/day).
// Register at https://hackertarget.com/membership/ for a key to increase limits.
// Used for reverse DNS, reverse IP, DNS lookup, and host search — informational only.
define('HACKERTARGET_API_KEY', '');  // optional — leave blank for free tier

// ─── EmailRep ─────────────────────────────────────────────────
define('EMAILREP_API_KEY',  '');   // https://emailrep.io

// ─── Custom Threat Lists ──────────────────────────────────────
// Define your own indicator lists below.
// Each entry requires:
//   'name' => Display name shown in UI
//   'type' => One of: 'IP', 'Domain', 'Email', 'Hash'
//   'url'  => Publicly accessible URL to a plain-text list (one entry per line)
//   'scoring' => How the list is handled: 'threats', 'information'
//
// For IP lists: supports plain IPs and CIDR notation (e.g. 192.168.1.0/24)
// For Domain lists: substring/partial matching is used
//
define('CUSTOM_LISTS', [
    [
        'name' => 'Emerging Threats IPs',
        'type' => 'IP',
        'url'  => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'scoring' => 'threats',
    ],
    [
        'name' => 'URLhaus Domains',
        'type' => 'Domain',
        'url'  => 'https://urlhaus.abuse.ch/downloads/text_online/',
        'scoring' => 'threats',
    ],
    [
        'name' => 'Example Hash Blocklist',
        'type' => 'Hash',
        'url'  => 'https://example.com/hashes.txt',
        'scoring' => 'threats',
    ],
    [
        'name' => 'Example Email Blocklist',
        'type' => 'Email',
        'url'  => 'https://example.com/emails.txt',
        'scoring' => 'threats',
    ],
]);

// ───
// ─── Hunt Configuration ──────────────────────────────────────────
// ───

define('HUNT_ELASTIC_URL',     'https://your-hunt-elastic:9200');
define('HUNT_ELASTIC_API_KEY', 'your-base64-api-key');
define('HUNT_ELASTIC_INDEX',   'logs-*');   // default, overridable per-search
define('HUNT_KIBANA_URL',      '');         // optional, enables ↗ Kibana links on hits

// ─── FortiAnalyzer — Hunt ─────────────────────────────────────
// Lets the Hunt page query a FortiAnalyzer instance instead of Elasticsearch.
// IPv4/IPv6 indicators search Traffic + VPN logs (source/destination IP, or
// VPN remote/assigned IP). Domain indicators search DNS + Web Filter logs.
define('FORTIANALYZER_URL',        '');      // e.g. https://faz.yourorg.local
define('FORTIANALYZER_ADOM',       'root');  // Administrative Domain to search
// Preferred: a REST API access token for a dedicated API admin (never expires,
// no session management). Leave blank to fall back to username/password below.
define('FORTIANALYZER_API_KEY',    '');
// Fallback: session-based login. Only used when FORTIANALYZER_API_KEY is blank.
define('FORTIANALYZER_USERNAME',   '');
define('FORTIANALYZER_PASSWORD',   '');
// Optional: restrict searches to one managed device (devname). Leave blank
// to search across all devices in the ADOM.
define('FORTIANALYZER_DEVICE',     '');
define('FORTIANALYZER_VERIFY_SSL', true);    // set false only for self-signed labs

// ───
// ─── History Setup ────────────────────────────────────────────────────
// ───

// ─── History storage ──────────────────────────────────────────
// Path to writable directory for storing lookup history JSON
define('HISTORY_FILE', __DIR__ . '/data/history.json');
define('HISTORY_MAX',  500);

// ─── Settings storage ─────────────────────────────────────────
// Settings updated via the UI panel are saved here
define('SETTINGS_FILE', __DIR__ . '/data/settings.json');

// ───
// ─── Security/Error Handling ────────────────────────────────────────────────────
// ───

// ─── Security ─────────────────────────────────────────────────
define('RATE_LIMIT_LOOKUPS', 20);   // Max lookups per minute per IP
define('RATE_LIMIT_LOGIN',   10);   // Max login attempts per 15 min per IP
define('RATE_LIMIT_FILE',    __DIR__ . '/data/rate_limits.json');

// ─── Error reporting ──────────────────────────────────────────
if (APP_ENV === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}
