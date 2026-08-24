<?php
declare(strict_types=1);

require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/token.php';
require_once __DIR__ . '/lib/ip.php';

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function env_value(string $key, string $default = ''): string
{
    $value = getenv($key);

    if ($value === false || trim((string)$value) === '') {
        return $default;
    }

    return trim((string)$value);
}

function env_bool(string $key, bool $default = false): bool
{
    $value = strtolower(env_value($key, $default ? '1' : '0'));

    return in_array($value, ['1', 'true', 'yes', 'on'], true);
}

function env_int(string $key, int $default): int
{
    $value = env_value($key, (string)$default);

    if (!is_numeric($value)) {
        return $default;
    }

    return (int)$value;
}

function get_access_ip_log_dir(): string
{
    return __DIR__ . '/../accsess-ip';
}

function ensure_access_ip_log_dir(): void
{
    $dir = get_access_ip_log_dir();

    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    if (!is_writable($dir)) {
        throw new RuntimeException('IP保存フォルダに書き込みできません: ' . $dir);
    }
}

function save_access_ip_log(array $data): void
{
    ensure_access_ip_log_dir();

    $dir = get_access_ip_log_dir();
    $file = $dir . '/access-ip-' . date('Y-m') . '.jsonl';

    $risk = $data['risk'] ?? [];

    if (is_array($risk)) {
        unset($risk['host']);
        unset($risk['ipqs']['raw']['host']);
    }

    $record = [
        'saved_at' => date('Y-m-d H:i:s'),
        'guild_id' => $data['guild_id'] ?? '',
        'user_id' => $data['user_id'] ?? '',
        'ip' => $data['ip'] ?? '',
        'ip_hash' => $data['ip_hash'] ?? '',
        'ip_country' => $data['ip_country'] ?? '',
        'status' => $data['status'] ?? '',
        'reason' => $data['reason'] ?? '',
        'risk' => $risk,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
        'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        'cf_connecting_ip' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''
    ];

    $json = json_encode(
        $record,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    if ($json === false) {
        throw new RuntimeException('IPログのJSON作成に失敗しました');
    }

    file_put_contents($file, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
    chmod($file, 0600);
}

function bool_from_array(array $data, array $keys): bool
{
    foreach ($keys as $key) {
        if (array_key_exists($key, $data)) {
            return filter_var($data[$key], FILTER_VALIDATE_BOOLEAN);
        }
    }

    return false;
}

function string_from_array(array $data, array $keys, string $default = ''): string
{
    foreach ($keys as $key) {
        if (isset($data[$key]) && $data[$key] !== '') {
            return (string)$data[$key];
        }
    }

    return $default;
}

function int_from_array(array $data, array $keys, int $default = 0): int
{
    foreach ($keys as $key) {
        if (isset($data[$key]) && is_numeric($data[$key])) {
            return (int)$data[$key];
        }
    }

    return $default;
}

function text_contains_any(string $text, array $keywords): bool
{
    $normalized = mb_strtolower($text, 'UTF-8');

    foreach ($keywords as $keyword) {
        $keyword = mb_strtolower($keyword, 'UTF-8');

        if ($keyword !== '' && str_contains($normalized, $keyword)) {
            return true;
        }
    }

    return false;
}

function is_trusted_japanese_residential_provider(string $countryCode, string $isp, string $organization, string $asn, string $host): bool
{
    if (strtoupper($countryCode) !== 'JP') {
        return false;
    }

    $text = implode(' ', [$isp, $organization, $asn, $host]);

    $trustedKeywords = [
        'eo hikari',
        'eonet',
        'k-opti',
        'optage',
        'ntt',
        'ocn',
        'plala',
        'docomo',
        'kddi',
        'au',
        'uq',
        'softbank',
        'bbtec',
        'yahoo',
        'rakuten',
        'j:com',
        'jcom',
        'jupiter',
        'sony',
        'nuro',
        'so-net',
        'biglobe',
        'iij',
        'iijmio',
        'mineo',
        'asahi net',
        'nifty',
        '@nifty',
        'commufa',
        'ctc',
        'tokai',
        'itscom',
        'arteria',
        'ucom',
        'usen',
        'hi-ho',
        'dti',
        'wakwak',
        'megaegg',
        'pikara',
        'bbix',
        'starcat',
        'zaq',
        'cable',
        'catv',
        'fiber',
        'hikari'
    ];

    if (text_contains_any($text, $trustedKeywords)) {
        return true;
    }

    $trustedAsn = [
        '17511',
        '2516',
        '4713',
        '9605',
        '17676',
        '10010',
        '2518',
        '2497',
        '4685',
        '17506',
        '2527'
    ];

    return in_array((string)$asn, $trustedAsn, true);
}

function is_cloud_or_vps_provider(string $isp, string $organization, string $asn, string $host): bool
{
    $text = implode(' ', [$isp, $organization, $asn, $host]);

    $cloudKeywords = [
        'amazon',
        'aws',
        'ec2',
        'google cloud',
        'google llc',
        'microsoft',
        'azure',
        'oracle',
        'oracle cloud',
        'digitalocean',
        'linode',
        'akamai',
        'vultr',
        'ovh',
        'hetzner',
        'contabo',
        'leaseweb',
        'm247',
        'choopa',
        'cloudflare',
        'fastly',
        'cdn77',
        'datacenter',
        'data center',
        'hosting',
        'hostinger',
        'server',
        'vps',
        'colo',
        'colocation',
        'sakura internet',
        'sakura',
        'conoha',
        'xserver',
        'xserver inc',
        'kagoya',
        'idc frontier',
        'gmo cloud',
        'gmo internet',
        'onamae',
        'lolipop',
        'mixhost',
        'heteml',
        'value-domain',
        'paperboy'
    ];

    if (text_contains_any($text, $cloudKeywords)) {
        return true;
    }

    $cloudAsn = [
        '16509',
        '14618',
        '15169',
        '8075',
        '31898',
        '14061',
        '63949',
        '20473',
        '16276',
        '24940',
        '51167',
        '9371',
        '9370',
        '7506',
        '131965',
        '24282',
        '24253'
    ];

    return in_array((string)$asn, $cloudAsn, true);
}

function fetch_ip_quality_score(string $ip): array
{
    $apiKey = env_value('IPQS_API_KEY', '');

    if ($apiKey === '') {
        return [
            'enabled' => false,
            'success' => false,
            'message' => 'IPQS_API_KEY is not set',
            'raw' => null
        ];
    }

    $query = http_build_query([
        'strictness' => 1,
        'allow_public_access_points' => 'false',
        'fast' => 'false',
        'lighter_penalties' => 'false'
    ]);

    $url = 'https://www.ipqualityscore.com/api/json/ip/' . rawurlencode($apiKey) . '/' . rawurlencode($ip) . '?' . $query;

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 5,
            'ignore_errors' => true,
            'header' => "User-Agent: DiscordVerifyBot/1.0\r\n"
        ]
    ]);

    $response = @file_get_contents($url, false, $context);

    if ($response === false) {
        return [
            'enabled' => true,
            'success' => false,
            'message' => 'IPQS request failed',
            'raw' => null
        ];
    }

    $json = json_decode($response, true);

    if (!is_array($json)) {
        return [
            'enabled' => true,
            'success' => false,
            'message' => 'IPQS returned invalid JSON',
            'raw' => $response
        ];
    }

    $success = filter_var($json['success'] ?? false, FILTER_VALIDATE_BOOLEAN);

    return [
        'enabled' => true,
        'success' => $success,
        'message' => (string)($json['message'] ?? ''),
        'raw' => $json
    ];
}

function analyze_ip_risk(string $ip): array
{
    $mode = strtolower(env_value('IP_RISK_MODE', 'log'));

    if (!in_array($mode, ['log', 'block'], true)) {
        $mode = 'log';
    }

    $scoreBlock = env_int('IP_RISK_SCORE_BLOCK', 90);
    $scoreReview = env_int('IP_RISK_SCORE_REVIEW', 60);

    $ipqs = fetch_ip_quality_score($ip);
    $raw = is_array($ipqs['raw'] ?? null) ? $ipqs['raw'] : [];

    $fraudScore = int_from_array($raw, ['fraud_score', 'risk_score'], 0);
    $countryCode = strtoupper(string_from_array($raw, ['country_code'], ''));
    $proxy = bool_from_array($raw, ['proxy']);
    $vpn = bool_from_array($raw, ['vpn']);
    $activeVpn = bool_from_array($raw, ['active_vpn']);
    $tor = bool_from_array($raw, ['tor']);
    $activeTor = bool_from_array($raw, ['active_tor']);
    $recentAbuse = bool_from_array($raw, ['recent_abuse']);
    $botStatus = bool_from_array($raw, ['bot_status']);
    $publicAccessPoint = bool_from_array($raw, ['public_access_point', 'public_access_points']);

    $connectionType = strtolower(string_from_array($raw, ['connection_type'], ''));
    $isp = string_from_array($raw, ['ISP', 'isp'], '');
    $organization = string_from_array($raw, ['organization', 'org'], '');
    $asn = (string)int_from_array($raw, ['ASN', 'asn'], 0);
    $host = string_from_array($raw, ['host'], '');

    $trustedResidential = is_trusted_japanese_residential_provider(
        $countryCode,
        $isp,
        $organization,
        $asn,
        $host
    );

    $cloudOrVps = is_cloud_or_vps_provider(
        $isp,
        $organization,
        $asn,
        $host
    );

    $hosting = false;

    if (
        str_contains($connectionType, 'hosting') ||
        str_contains($connectionType, 'data center') ||
        str_contains($connectionType, 'datacenter') ||
        str_contains($connectionType, 'server')
    ) {
        $hosting = true;
    }

    if ($cloudOrVps) {
        $hosting = true;
    }

    $detectedReasons = [];
    $blockReasons = [];

    if ($proxy) {
        $detectedReasons[] = 'proxy';
    }

    if ($vpn) {
        $detectedReasons[] = 'vpn';
    }

    if ($activeVpn) {
        $detectedReasons[] = 'active_vpn';
    }

    if ($tor) {
        $detectedReasons[] = 'tor';
    }

    if ($activeTor) {
        $detectedReasons[] = 'active_tor';
    }

    if ($recentAbuse) {
        $detectedReasons[] = 'recent_abuse';
    }

    if ($botStatus) {
        $detectedReasons[] = 'bot_status';
    }

    if ($publicAccessPoint) {
        $detectedReasons[] = 'public_access_point';
    }

    if ($hosting) {
        $detectedReasons[] = 'hosting_or_datacenter';
    }

    if ($fraudScore >= $scoreReview) {
        $detectedReasons[] = 'review_score_' . $fraudScore;
    }

    if (env_bool('BLOCK_TOR_IP', true) && ($tor || $activeTor)) {
        $blockReasons[] = 'tor';
    }

    if (env_bool('BLOCK_VPN_IP', true) && $activeVpn) {
        $blockReasons[] = 'active_vpn';
    }

    if (env_bool('BLOCK_VPN_IP', true) && $vpn && !$trustedResidential && $fraudScore >= 60) {
        $blockReasons[] = 'vpn_non_residential';
    }

    if (env_bool('BLOCK_HOSTING_IP', true) && $hosting && !$trustedResidential) {
        $blockReasons[] = 'hosting_or_datacenter';
    }

    if (env_bool('BLOCK_PROXY_IP', true) && $proxy && !$trustedResidential && ($fraudScore >= $scoreBlock || $hosting)) {
        $blockReasons[] = 'proxy_high_risk';
    }

    if (env_bool('BLOCK_PUBLIC_ACCESS_POINTS', true) && $publicAccessPoint && !$trustedResidential) {
        $blockReasons[] = 'public_access_point';
    }

    if (!$trustedResidential && $fraudScore >= $scoreBlock) {
        $blockReasons[] = 'high_risk_score';
    }

    if ($trustedResidential && $fraudScore >= 95 && ($proxy || $vpn || $recentAbuse || $botStatus)) {
        $blockReasons[] = 'trusted_residential_extreme_risk';
    }

    if (!$trustedResidential && $recentAbuse && $botStatus && $fraudScore >= 75) {
        $blockReasons[] = 'recent_abuse_bot_status';
    }

    $shouldBlock = $mode === 'block' && count($blockReasons) > 0;

    $review = false;

    if ($fraudScore >= $scoreReview || count($detectedReasons) > 0 || $ipqs['success'] === false) {
        $review = true;
    }

    return [
        'mode' => $mode,
        'should_block' => $shouldBlock,
        'review' => $review,
        'reasons' => $detectedReasons,
        'block_reasons' => $blockReasons,
        'fraud_score' => $fraudScore,
        'country_code' => $countryCode,
        'proxy' => $proxy,
        'vpn' => $vpn,
        'active_vpn' => $activeVpn,
        'tor' => $tor,
        'active_tor' => $activeTor,
        'hosting' => $hosting,
        'cloud_or_vps' => $cloudOrVps,
        'trusted_residential' => $trustedResidential,
        'public_access_point' => $publicAccessPoint,
        'recent_abuse' => $recentAbuse,
        'bot_status' => $botStatus,
        'connection_type' => $connectionType,
        'isp' => $isp,
        'organization' => $organization,
        'asn' => $asn,
        'ipqs' => $ipqs
    ];
}

function render_verify_page(string $status, string $title, string $message, array $details = []): void
{
    $statusClass = 'wait';
    $badge = '処理中';

    if ($status === 'approved') {
        $statusClass = 'approved';
        $badge = '認証成功';
    } elseif (
        $status === 'blocked_country' ||
        $status === 'blocked_duplicate' ||
        $status === 'blocked_same_user' ||
        $status === 'blocked_provider'
    ) {
        $statusClass = 'blocked';
        $badge = '認証失敗';
    } elseif ($status === 'error') {
        $statusClass = 'error';
        $badge = 'エラー';
    }

    echo '<!doctype html>';
    echo '<html lang="ja">';
    echo '<head>';
    echo '<meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . '</title>';

    echo '<style>';
    echo <<<CSS
* {
  box-sizing: border-box;
}

:root {
  --bg: #000000;
  --grid: rgba(145,145,145,0.18);
  --card: #0b0b0b;
  --border: #2a2a2a;
  --text: #ffffff;
  --muted: #bdbdbd;
  --green: #38d66b;
  --red: #ff4d4f;
  --yellow: #f4c542;
}

html,
body {
  margin: 0;
  padding: 0;
  min-height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Yu Gothic", sans-serif;
}

body {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  position: relative;
  overflow: hidden;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(var(--grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
}

.wrap {
  width: min(680px, 100%);
  position: relative;
  z-index: 1;
}

.card {
  background: rgba(10, 10, 10, 0.96);
  border: 1px solid var(--border);
  border-radius: 20px;
  overflow: hidden;
  box-shadow:
    0 0 0 1px rgba(255,255,255,0.02),
    0 25px 60px rgba(0,0,0,0.6);
}

.bar {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: .08em;
  color: var(--muted);
}

.content {
  padding: 36px 28px;
  text-align: center;
}

.result-title {
  margin: 0 0 14px;
  font-size: clamp(28px, 5vw, 42px);
  font-weight: 800;
  letter-spacing: -0.03em;
}

.result-message {
  margin: 0;
  font-size: 16px;
  line-height: 1.8;
  color: var(--muted);
}

.details {
  margin-top: 26px;
  display: grid;
  gap: 10px;
}

.row {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 16px;
  border-radius: 12px;
  background: #111111;
  border: 1px solid #222222;
}

.key {
  color: #a8a8a8;
  font-weight: 700;
}

.value {
  color: #ffffff;
  font-weight: 700;
  text-align: right;
}

.approved .bar {
  color: var(--green);
}

.blocked .bar {
  color: var(--red);
}

.error .bar {
  color: var(--yellow);
}

@media (max-width: 640px) {
  .content {
    padding: 28px 18px;
  }

  .row {
    display: block;
    text-align: left;
  }

  .value {
    display: block;
    text-align: left;
    margin-top: 6px;
  }
}
CSS;
    echo '</style>';
    echo '</head>';

    echo '<body>';
    echo '<main class="wrap">';
    echo '<section class="card ' . h($statusClass) . '">';
    echo '<div class="bar">' . h($badge) . '</div>';
    echo '<div class="content">';
    echo '<h1 class="result-title">' . h($title) . '</h1>';
    echo '<p class="result-message">' . h($message) . '</p>';

    if (!empty($details)) {
        echo '<div class="details">';

        foreach ($details as $key => $value) {
            echo '<div class="row">';
            echo '<span class="key">' . h((string)$key) . '</span>';
            echo '<span class="value">' . h((string)$value) . '</span>';
            echo '</div>';
        }

        echo '</div>';
    }

    echo '</div>';
    echo '</section>';
    echo '</main>';
    echo '</body>';
    echo '</html>';
}

try {
    $token = $_GET['token'] ?? '';

    if (!is_string($token) || trim($token) === '') {
        http_response_code(400);

        render_verify_page(
            'error',
            '認証リンクが無効です',
            '認証用リンクが見つかりません。Discordの認証ボタンから再度やり直してください。'
        );

        exit;
    }

    $payload = discord_verify_token_payload($token, $config['verify_token_secret']);

    if ($payload === null) {
        http_response_code(400);

        render_verify_page(
            'error',
            '認証リンクの期限が切れています',
            'この認証リンクは無効、または期限切れです。Discordから新しい認証リンクを発行してください。'
        );

        exit;
    }

    $guildId = $payload['guildId'];
    $userId = $payload['userId'];
    $tokenHash = hash('sha256', $token);

    $existingTokenStmt = $pdo->prepare(
        'SELECT status, ip_country, created_at
         FROM verifications
         WHERE token_hash = ?
         LIMIT 1'
    );

    $existingTokenStmt->execute([$tokenHash]);
    $existingToken = $existingTokenStmt->fetch();

    if ($existingToken) {
        $existingStatus = (string)$existingToken['status'];

        render_verify_page(
            $existingStatus,
            'この認証リンクは使用済みです',
            'この認証リンクはすでに処理されています。Discordから新しいリンクを発行してください。',
            [
                '状態' => $existingStatus,
                '日時' => (string)$existingToken['created_at']
            ]
        );

        exit;
    }

    $ip = discord_verify_client_ip();

    if ($ip === '') {
        http_response_code(400);

        render_verify_page(
            'error',
            'IPアドレスを取得できません',
            '接続元情報を取得できませんでした。時間をおいて再度お試しください。'
        );

        exit;
    }

    $country = discord_verify_country_of_ip($ip, $config);
    $allowedCountry = strtoupper($config['allowed_country']);
    $isAllowedCountry = strtoupper($country) === $allowedCountry;
    $ipHash = discord_verify_ip_hash($ip, $config['ip_hash_salt']);
    $userAgentHash = discord_verify_user_agent_hash($config['ip_hash_salt']);
    $risk = analyze_ip_risk($ip);

    $sameUserStmt = $pdo->prepare(
        'SELECT id, status, created_at
         FROM verifications
         WHERE guild_id = ?
           AND user_id = ?
           AND status = "approved"
         LIMIT 1'
    );

    $sameUserStmt->execute([$guildId, $userId]);
    $sameUserRecord = $sameUserStmt->fetch();
    $isSameUserAlreadyApproved = $sameUserRecord ? true : false;

    $duplicateStmt = $pdo->prepare(
        'SELECT id, user_id
         FROM verifications
         WHERE guild_id = ?
           AND ip_hash = ?
           AND user_id <> ?
           AND status = "approved"
         LIMIT 1'
    );

    $duplicateStmt->execute([$guildId, $ipHash, $userId]);
    $duplicateRecord = $duplicateStmt->fetch();
    $isDuplicateIp = $duplicateRecord ? true : false;

    $status = 'approved';
    $reason = 'approved';

    if (!$isAllowedCountry) {
        $status = 'blocked_country';
        $reason = 'blocked_country';
    } elseif ($isSameUserAlreadyApproved) {
        $status = 'blocked_same_user';
        $reason = 'same_user_already_approved';
    } elseif ($isDuplicateIp) {
        $status = 'blocked_duplicate';
        $reason = 'duplicate_ip';
    } elseif ($risk['should_block']) {
        $status = 'blocked_provider';
        $reason = 'provider_risk_' . implode('_', $risk['block_reasons']);
    }

    save_access_ip_log([
        'guild_id' => $guildId,
        'user_id' => $userId,
        'ip' => $ip,
        'ip_hash' => $ipHash,
        'ip_country' => $country,
        'status' => $status,
        'reason' => $reason,
        'risk' => $risk
    ]);

    $insertStmt = $pdo->prepare(
        'INSERT INTO verifications
         (
           guild_id,
           user_id,
           token_hash,
           ip_hash,
           ip_country,
           is_allowed_country,
           is_duplicate_ip,
           status,
           processed,
           user_agent_hash,
           risk_isp,
           risk_organization,
           risk_asn,
           risk_score,
           risk_flags
         )
         VALUES
         (
           :guild_id,
           :user_id,
           :token_hash,
           :ip_hash,
           :ip_country,
           :is_allowed_country,
           :is_duplicate_ip,
           :status,
           0,
           :user_agent_hash,
           :risk_isp,
           :risk_organization,
           :risk_asn,
           :risk_score,
           :risk_flags
         )'
    );

    $riskFlags = '';

    if (isset($risk['block_reasons']) && is_array($risk['block_reasons']) && count($risk['block_reasons']) > 0) {
        $riskFlags = implode(',', $risk['block_reasons']);
    } elseif (isset($risk['reasons']) && is_array($risk['reasons'])) {
        $riskFlags = implode(',', $risk['reasons']);
    }

    $insertStmt->execute([
        ':guild_id' => $guildId,
        ':user_id' => $userId,
        ':token_hash' => $tokenHash,
        ':ip_hash' => $ipHash,
        ':ip_country' => $country,
        ':is_allowed_country' => $isAllowedCountry ? 1 : 0,
        ':is_duplicate_ip' => $isDuplicateIp ? 1 : 0,
        ':status' => $status,
        ':user_agent_hash' => $userAgentHash,
        ':risk_isp' => $risk['isp'] ?? null,
        ':risk_organization' => $risk['organization'] ?? null,
        ':risk_asn' => $risk['asn'] ?? null,
        ':risk_score' => $risk['fraud_score'] ?? null,
        ':risk_flags' => $riskFlags
    ]);

    if ($status === 'approved') {
        render_verify_page(
            'approved',
            '認証が完了しました',
            '認証に成功しました。Discordに戻ってください。',
            [
                '状態' => '認証成功'
            ]
        );

        exit;
    }

    if ($status === 'blocked_country') {
        render_verify_page(
            'blocked_country',
            '認証に失敗しました',
            'この接続元からは認証できません。必要であれば管理者に連絡してください。',
            [
                '状態' => '国制限によりブロック'
            ]
        );

        exit;
    }

    if ($status === 'blocked_same_user') {
        render_verify_page(
            'blocked_same_user',
            '認証に失敗しました',
            'このDiscordアカウントはすでに認証済みです。もう一度認証することはできません。',
            [
                '状態' => '同じIDの再認証をブロック'
            ]
        );

        exit;
    }

    if ($status === 'blocked_provider') {
        render_verify_page(
            'blocked_provider',
            '認証に失敗しました',
            'プロパイダーの問題により認証がブロックされました。ご自宅に帰宅後、再度認証をお願いいたします。',
            [
                '状態' => 'プロパイダー判定によりブロック'
            ]
        );

        exit;
    }

    render_verify_page(
        'blocked_duplicate',
        '認証に失敗しました',
        '同じサーバー内で、すでに別アカウントによる認証済みIPが確認されています。必要であれば管理者に連絡してください。',
        [
            '状態' => '重複IPによりブロック'
        ]
    );

    exit;
} catch (Throwable $e) {
    http_response_code(500);

    render_verify_page(
        'error',
        'サーバーエラー',
        '認証処理中にエラーが発生しました。時間をおいて再度お試しください。',
        [
            '詳細' => $e->getMessage()
        ]
    );

    exit;
}