<?php
/**
 * IndiansCloud provisioning module for WHMCS.
 *
 * Talks to the IndiansCloud panel's provisioning API v2 (https://<server hostname>:8090/api/v2/)
 * with a personal API token sent as "Authorization: Bearer ictk_...".
 *
 * Server settings (Setup > Products/Services > Servers):
 *   Hostname     panel hostname (the TLS certificate must match it unless self-signed is allowed)
 *   Port         8090 (default; "Override with Custom Port" to change)
 *   Username     the panel account that owns the token (optional; used as a cross-check)
 *   Password     the API token (ictk_...), or put it in Access Hash
 *   Access Hash  either the token alone, or key=value lines:
 *                  token=ictk_...
 *                  allow_self_signed=1      (skip TLS verification; testing only)
 *                  ca_file=/path/to/ca.pem  (trust a private CA instead)
 *
 * Compatible with PHP 7.4 and 8.x.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

define('INDIANSCLOUD_DEFAULT_PORT', 8090);
define('INDIANSCLOUD_TIMEOUT', 120);

function indianscloud_MetaData()
{
    return array(
        'DisplayName' => 'IndiansCloud',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
        'DefaultNonSSLPort' => '8090',
        'DefaultSSLPort' => '8090',
        'ServiceSingleSignOnLabel' => 'Log in to IndiansCloud',
        'AdminSingleSignOnLabel' => 'Log in to IndiansCloud',
    );
}

function indianscloud_ConfigOptions()
{
    return array(
        'Package Name' => array(
            'Type' => 'text',
            'Size' => '30',
            'Default' => 'Default',
            'Description' => 'Exact panel package name (for example admin_Starter). A reseller token may also give the name without its "username_" prefix.',
        ),
        'PHP Version' => array(
            'Type' => 'dropdown',
            'Options' => 'PHP 7.4,PHP 8.0,PHP 8.1,PHP 8.2,PHP 8.3,PHP 8.4',
            'Default' => 'PHP 8.2',
            'Description' => 'PHP version of the first website',
        ),
        'Reseller Account' => array(
            'Type' => 'yesno',
            'Description' => 'Create a reseller account (ACL "reseller" unless the ACL below says otherwise)',
        ),
        'ACL' => array(
            'Type' => 'text',
            'Size' => '20',
            'Default' => '',
            'Description' => 'Panel ACL name; empty means "user", or "reseller" when Reseller Account is ticked',
        ),
        'Websites Limit' => array(
            'Type' => 'text',
            'Size' => '6',
            'Default' => '1',
            'Description' => 'How many websites the account may create (0 = unlimited for resellers)',
        ),
    );
}

/* ------------------------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------------------------- */

/** Parse the server credentials: token, TLS options. */
function indianscloud_credentials(array $params)
{
    $options = array('token' => '', 'allow_self_signed' => false, 'ca_file' => '');
    $hash = trim(isset($params['serveraccesshash']) ? (string) $params['serveraccesshash'] : '');
    if ($hash !== '') {
        if (strpos($hash, '=') === false && strpos($hash, "\n") === false) {
            $options['token'] = $hash;
        } else {
            foreach (preg_split('/\r\n|\r|\n/', $hash) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
                    continue;
                }
                list($key, $value) = array_map('trim', explode('=', $line, 2));
                $key = strtolower($key);
                if ($key === 'token') {
                    $options['token'] = $value;
                } elseif ($key === 'allow_self_signed') {
                    $options['allow_self_signed'] = in_array(strtolower($value), array('1', 'yes', 'true', 'on'), true);
                } elseif ($key === 'ca_file') {
                    $options['ca_file'] = $value;
                }
            }
        }
    }
    $password = isset($params['serverpassword']) ? trim((string) $params['serverpassword']) : '';
    if (strpos($password, 'ictk_') === 0) {
        $options['token'] = $password;    // the Password field wins: WHMCS stores it encrypted
    }
    return $options;
}

function indianscloud_base_url(array $params)
{
    $host = '';
    foreach (array('serverhostname', 'serverip') as $key) {
        if (!empty($params[$key])) {
            $host = trim((string) $params[$key]);
            break;
        }
    }
    $host = preg_replace('#^https?://#i', '', $host);
    $host = rtrim($host, '/');
    if (strpos($host, ':') !== false && strpos($host, ']') === false && substr_count($host, ':') === 1) {
        $host = substr($host, 0, strpos($host, ':'));   // a port typed into the hostname field
    }
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $host = '[' . $host . ']';
    }
    $port = !empty($params['serverport']) ? (int) $params['serverport'] : INDIANSCLOUD_DEFAULT_PORT;
    return 'https://' . $host . ':' . $port . '/api/v2/';
}

/** Characters the panel's request filter refuses in API values. */
function indianscloud_clean_text($value, $max = 200)
{
    $value = preg_replace('/[\x00-\x1f\x7f;|`$]|&&|\.\.\./', ' ', (string) $value);
    return substr(trim($value), 0, $max);
}

/**
 * Call the panel. Returns the decoded JSON array; throws Exception with a readable message.
 * Tests replace the transport through $GLOBALS['indianscloud_transport'].
 */
function indianscloud_call(array $params, $endpoint, array $payload = array())
{
    $credentials = indianscloud_credentials($params);
    if ($credentials['token'] === '') {
        throw new Exception('No API token: put an IndiansCloud token (ictk_...) in the server Password or Access Hash field.');
    }
    $url = indianscloud_base_url($params) . $endpoint;
    $body = json_encode($payload);
    $headers = array(
        'Content-Type: application/json',
        'Accept: application/json',
        'Authorization: Bearer ' . $credentials['token'],
    );

    if (isset($GLOBALS['indianscloud_transport']) && is_callable($GLOBALS['indianscloud_transport'])) {
        $result = call_user_func($GLOBALS['indianscloud_transport'], $url, $headers, $body, $credentials);
        $raw = $result[0];
        $httpCode = $result[1];
        $error = isset($result[2]) ? $result[2] : '';
    } else {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($ch, CURLOPT_TIMEOUT, INDIANSCLOUD_TIMEOUT);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        if ($credentials['allow_self_signed']) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            if ($credentials['ca_file'] !== '') {
                curl_setopt($ch, CURLOPT_CAINFO, $credentials['ca_file']);
            }
        }
        $raw = curl_exec($ch);
        $error = $raw === false ? curl_error($ch) : '';
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    }

    $logged = $payload;
    foreach (array('password', 'passwordB64') as $secret) {
        if (isset($logged[$secret])) {
            $logged[$secret] = '********';
        }
    }
    if (function_exists('logModuleCall')) {
        logModuleCall('indianscloud', $endpoint, $logged, $raw, null,
            array($credentials['token'], isset($payload['passwordB64']) ? $payload['passwordB64'] : ''));
    }

    if ($raw === false || $raw === null || $raw === '') {
        throw new Exception('Could not reach the panel at ' . $url . ($error ? ': ' . $error : '')
            . '. Check the hostname, port 8090 in the firewall and the TLS certificate.');
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        throw new Exception('The panel returned an unexpected response (HTTP ' . $httpCode . ').');
    }
    if (!isset($data['status']) || (int) $data['status'] !== 1) {
        $message = isset($data['error_message']) ? $data['error_message'] : (isset($data['errorMessage']) ? $data['errorMessage'] : 'Unknown error');
        throw new Exception($message . ' (HTTP ' . $httpCode . ')');
    }
    return $data;
}

/** Map a WHMCS service to panel values. */
function indianscloud_service_map(array $params)
{
    $username = strtolower(trim(isset($params['username']) ? (string) $params['username'] : ''));
    $domain = strtolower(trim(isset($params['domain']) ? (string) $params['domain'] : ''));
    $domain = preg_replace('#^https?://#', '', $domain);
    $domain = rtrim(preg_replace('#/.*$#', '', $domain), '.');
    if (strpos($domain, 'www.') === 0) {
        $domain = substr($domain, 4);
    }
    $reseller = !empty($params['configoption3']) && $params['configoption3'] !== 'off';
    $acl = trim(isset($params['configoption4']) ? (string) $params['configoption4'] : '');
    if ($acl === '') {
        $acl = $reseller ? 'reseller' : 'user';
    }
    $package = trim(isset($params['configoption1']) ? (string) $params['configoption1'] : '');
    // A configurable option or custom field named "Package" overrides the product's package.
    foreach (array('configoptions', 'customfields') as $group) {
        if (!empty($params[$group]['Package'])) {
            $package = trim((string) $params[$group]['Package']);
        }
    }
    $limit = isset($params['configoption5']) && $params['configoption5'] !== '' ? (int) $params['configoption5'] : 1;
    $php = !empty($params['configoption2']) ? $params['configoption2'] : 'PHP 8.2';
    $client = isset($params['clientsdetails']) && is_array($params['clientsdetails']) ? $params['clientsdetails'] : array();
    return array(
        'username' => $username,
        'domain' => $domain,
        'package' => $package === '' ? 'Default' : $package,
        'php' => $php,
        'acl' => $acl,
        'reseller' => $reseller,
        'websitesLimit' => $limit,
        'email' => isset($client['email']) ? $client['email'] : '',
        'firstName' => indianscloud_clean_text(isset($client['firstname']) ? $client['firstname'] : '', 50),
        'lastName' => indianscloud_clean_text(isset($client['lastname']) ? $client['lastname'] : '', 50),
    );
}

/** A panel username from WHMCS's username, or from the domain when WHMCS left it empty. */
function indianscloud_panel_username($username, $domain)
{
    $username = strtolower(preg_replace('/[^a-z0-9_.-]/i', '', (string) $username));
    if (preg_match('/^[a-z0-9][a-z0-9_.-]{2,49}$/', $username)) {
        return $username;
    }
    $base = substr(preg_replace('/[^a-z0-9]/', '', strtolower((string) $domain)), 0, 8);
    if ($base === '' || !ctype_alnum($base[0])) {
        $base = 'ic';
    }
    return $base . mt_rand(100, 999);
}

function indianscloud_save_username(array $params, $username)
{
    if (empty($params['serviceid']) || !class_exists('\WHMCS\Database\Capsule')) {
        return;
    }
    try {
        \WHMCS\Database\Capsule::table('tblhosting')->where('id', (int) $params['serviceid'])
            ->update(array('username' => $username));
    } catch (Exception $e) {
        // not fatal: the account exists; an administrator can correct the username field
    }
}

function indianscloud_error(Exception $e)
{
    $message = $e->getMessage();
    return $message === '' ? 'Unknown error' : $message;
}

/* ------------------------------------------------------------------------------------------
 * Module functions
 * ---------------------------------------------------------------------------------------- */

function indianscloud_TestConnection(array $params)
{
    try {
        $data = indianscloud_call($params, 'verify');
        $expected = isset($params['serverusername']) ? trim((string) $params['serverusername']) : '';
        if ($expected !== '' && strcasecmp($expected, $data['username']) !== 0) {
            return array('success' => false, 'error' => 'The token belongs to "' . $data['username']
                . '", not to the server username "' . $expected . '".');
        }
        if (!in_array('provisioning', isset($data['scopes']) ? $data['scopes'] : array(), true)) {
            return array('success' => false, 'error' => 'The token is read-only; create one with the Provisioning scope.');
        }
        return array('success' => true, 'error' => '');
    } catch (Exception $e) {
        return array('success' => false, 'error' => indianscloud_error($e));
    }
}

function indianscloud_CreateAccount(array $params)
{
    try {
        $map = indianscloud_service_map($params);
        $username = indianscloud_panel_username($map['username'], $map['domain']);
        if ($map['domain'] === '' && !$map['reseller']) {
            return 'This product needs a domain: the panel creates the website for it.';
        }
        if (empty($params['password']) || strlen($params['password']) < 8) {
            return 'The service password must be at least 8 characters.';
        }
        indianscloud_call($params, 'accounts/create', array(
            'username' => $username,
            'email' => $map['email'],
            'passwordB64' => base64_encode((string) $params['password']),
            'domain' => $map['domain'],
            'package' => $map['package'],
            'php' => $map['php'],
            'acl' => $map['acl'],
            'websitesLimit' => $map['websitesLimit'],
            'firstName' => $map['firstName'],
            'lastName' => $map['lastName'],
        ));
        if ($username !== $map['username']) {
            indianscloud_save_username($params, $username);
        }
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_SuspendAccount(array $params)
{
    try {
        $reason = isset($params['suspendreason']) ? indianscloud_clean_text($params['suspendreason']) : '';
        indianscloud_call($params, 'accounts/suspend', array('username' => $params['username'], 'reason' => $reason));
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_UnsuspendAccount(array $params)
{
    try {
        indianscloud_call($params, 'accounts/unsuspend', array('username' => $params['username']));
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_TerminateAccount(array $params)
{
    try {
        indianscloud_call($params, 'accounts/terminate', array('username' => $params['username']));
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_ChangePassword(array $params)
{
    try {
        indianscloud_call($params, 'accounts/password', array(
            'username' => $params['username'],
            'passwordB64' => base64_encode((string) $params['password']),
        ));
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_ChangePackage(array $params)
{
    try {
        $map = indianscloud_service_map($params);
        indianscloud_call($params, 'accounts/package', array('username' => $params['username'], 'package' => $map['package']));
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

/** Disk and bandwidth of every account on this server into tblhosting (runs from the daily cron). */
function indianscloud_UsageUpdate(array $params)
{
    try {
        $data = indianscloud_call($params, 'accounts/usage');
        $rows = array();
        foreach ($data['usage'] as $account) {
            $total = $account['total'];
            $rows[strtolower($account['username'])] = array(
                'diskusage' => (int) round($total['disk_mb']),
                'disklimit' => (int) $total['disk_limit_mb'],
                'bwusage' => (int) round($total['bandwidth_mb']),
                'bwlimit' => (int) $total['bandwidth_limit_mb'],
                'domains' => array_map(function ($site) { return $site['domain']; }, $account['sites']),
            );
        }
        if (isset($GLOBALS['indianscloud_usage_writer']) && is_callable($GLOBALS['indianscloud_usage_writer'])) {
            call_user_func($GLOBALS['indianscloud_usage_writer'], $params['serverid'], $rows);
            return 'success';
        }
        $services = \WHMCS\Database\Capsule::table('tblhosting')->where('server', (int) $params['serverid'])
            ->whereIn('domainstatus', array('Active', 'Suspended'))->get(array('id', 'username', 'domain'));
        foreach ($services as $service) {
            $key = strtolower((string) $service->username);
            $usage = isset($rows[$key]) ? $rows[$key] : null;
            if ($usage === null) {        // fall back to the domain
                foreach ($rows as $candidate) {
                    if (in_array(strtolower((string) $service->domain), $candidate['domains'], true)) {
                        $usage = $candidate;
                        break;
                    }
                }
            }
            if ($usage === null) {
                continue;
            }
            \WHMCS\Database\Capsule::table('tblhosting')->where('id', $service->id)->update(array(
                'diskusage' => $usage['diskusage'],
                'disklimit' => $usage['disklimit'],
                'bwusage' => $usage['bwusage'],
                'bwlimit' => $usage['bwlimit'],
                'lastupdate' => date('Y-m-d H:i:s'),
            ));
        }
        return 'success';
    } catch (Exception $e) {
        return indianscloud_error($e);
    }
}

function indianscloud_ServiceSingleSignOn(array $params)
{
    try {
        $payload = array('username' => $params['username']);
        if (!empty($params['app']) && preg_match('#^/[A-Za-z0-9/_.\-]{0,190}$#', $params['app'])) {
            $payload['redirect'] = $params['app'];
        }
        $data = indianscloud_call($params, 'sso', $payload);
        return array('success' => true, 'redirectTo' => $data['url']);
    } catch (Exception $e) {
        return array('success' => false, 'errorMsg' => indianscloud_error($e));
    }
}

/** Logs the WHMCS administrator into the panel as the token's own account. */
function indianscloud_AdminSingleSignOn(array $params)
{
    try {
        $data = indianscloud_call($params, 'sso', array());
        return array('success' => true, 'redirectTo' => $data['url']);
    } catch (Exception $e) {
        return array('success' => false, 'errorMsg' => indianscloud_error($e));
    }
}

function indianscloud_ClientArea(array $params)
{
    $vars = array(
        'panelUrl' => preg_replace('#/api/v2/$#', '/', indianscloud_base_url($params)),
        'username' => isset($params['username']) ? $params['username'] : '',
        'domain' => isset($params['domain']) ? $params['domain'] : '',
        'usage' => null,
        'error' => '',
    );
    try {
        $data = indianscloud_call($params, 'accounts/usage', array('username' => $params['username']));
        $vars['usage'] = isset($data['usage'][0]) ? $data['usage'][0] : null;
    } catch (Exception $e) {
        $vars['error'] = 'Usage is not available right now.';
    }
    return array(
        'tabOverviewReplacementTemplate' => 'templates/overview.tpl',
        'templateVariables' => $vars,
    );
}

function indianscloud_AdminServicesTabFields(array $params)
{
    try {
        $data = indianscloud_call($params, 'accounts/info', array('username' => $params['username']));
        $account = $data['account'];
        return array(
            'Panel account' => htmlspecialchars($account['username'] . ' (' . $account['acl'] . ', ' . $account['state'] . ')'),
            'Websites' => htmlspecialchars(implode(', ', $account['websites'])),
        );
    } catch (Exception $e) {
        return array('Panel account' => htmlspecialchars(indianscloud_error($e)));
    }
}
