<?php
/**
 * Unit-ish tests for the IndiansCloud WHMCS module, without WHMCS or a panel.
 * Run: php tests/run_tests.php   (exit code 0 = all passed)
 * The HTTP transport and the usage writer are replaced by recorders.
 */
define('WHMCS', true);
require __DIR__ . '/../indianscloud.php';

$GLOBALS['calls'] = array();
$GLOBALS['next'] = array();
$GLOBALS['indianscloud_transport'] = function ($url, $headers, $body, $credentials) {
    $GLOBALS['calls'][] = array('url' => $url, 'headers' => $headers, 'body' => json_decode($body, true),
                                'credentials' => $credentials);
    $reply = array_shift($GLOBALS['next']);
    if ($reply === null) {
        $reply = array('status' => 1);
    }
    return array(is_string($reply) ? $reply : json_encode($reply), 200, '');
};

$failures = 0;
$count = 0;
function check($label, $condition)
{
    global $failures, $count;
    $count++;
    if (!$condition) {
        $failures++;
        echo "FAIL: $label\n";
    }
}
function reset_calls($replies = array())
{
    $GLOBALS['calls'] = array();
    $GLOBALS['next'] = $replies;
}
function last_call()
{
    return end($GLOBALS['calls']);
}

$token = 'ictk_0123456789abcdef_' . str_repeat('A', 43);
$server = array('serverhostname' => 'panel.example.com', 'serverpassword' => $token, 'serverusername' => 'reseller',
                'serveraccesshash' => '', 'serverid' => 3);
$service = array_merge($server, array(
    'serviceid' => 9, 'username' => 'Shop1', 'password' => 'Pa$$w0rd;|x', 'domain' => 'WWW.Shop.Example.',
    'configoption1' => 'Starter', 'configoption2' => 'PHP 8.3', 'configoption3' => '', 'configoption4' => '',
    'configoption5' => '1', 'clientsdetails' => array('email' => 'c@example.com', 'firstname' => 'Ana;', 'lastname' => 'Rao'),
));

// metadata and options
$meta = indianscloud_MetaData();
check('metadata port', $meta['DefaultSSLPort'] === '8090');
check('config options', count(indianscloud_ConfigOptions()) === 5);

// credentials
$c = indianscloud_credentials(array('serveraccesshash' => "token=$token\nallow_self_signed=1"));
check('access hash token', $c['token'] === $token && $c['allow_self_signed'] === true);
$c = indianscloud_credentials(array('serveraccesshash' => $token));
check('bare access hash', $c['token'] === $token && $c['allow_self_signed'] === false);
check('base url', indianscloud_base_url($server) === 'https://panel.example.com:8090/api/v2/');
check('base url custom port', indianscloud_base_url(array_merge($server, array('serverport' => 2083))) === 'https://panel.example.com:2083/api/v2/');

// TestConnection
reset_calls(array(array('status' => 1, 'username' => 'reseller', 'scopes' => array('read', 'provisioning'))));
$r = indianscloud_TestConnection($server);
check('test connection ok', $r['success'] === true);
check('bearer header', in_array('Authorization: Bearer ' . $token, last_call()['headers'], true));
check('tls verified by default', last_call()['credentials']['allow_self_signed'] === false);
reset_calls(array(array('status' => 1, 'username' => 'reseller', 'scopes' => array('read'))));
$r = indianscloud_TestConnection($server);
check('read-only token refused', $r['success'] === false && strpos($r['error'], 'read-only') !== false);
reset_calls(array(array('status' => 0, 'error_message' => 'Could not authorize access to API.')));
$r = indianscloud_TestConnection($server);
check('auth error surfaced', $r['success'] === false && strpos($r['error'], 'Could not authorize') === 0);
$r = indianscloud_TestConnection(array('serverhostname' => 'x', 'serverpassword' => ''));
check('missing token', $r['success'] === false && strpos($r['error'], 'No API token') === 0);

// CreateAccount: mapping
reset_calls();
check('create success', indianscloud_CreateAccount($service) === 'success');
$call = last_call();
check('create endpoint', substr($call['url'], -15) === 'accounts/create');
check('username lowercased', $call['body']['username'] === 'shop1');
check('domain normalised', $call['body']['domain'] === 'shop.example');
check('password base64', base64_decode($call['body']['passwordB64']) === 'Pa$$w0rd;|x' && !isset($call['body']['password']));
check('package/php/acl', $call['body']['package'] === 'Starter' && $call['body']['php'] === 'PHP 8.3' && $call['body']['acl'] === 'user');
check('name cleaned', $call['body']['firstName'] === 'Ana');
reset_calls(array(array('status' => 0, 'error_message' => 'Username already exists: shop1')));
check('create error string', indianscloud_CreateAccount($service) === 'Username already exists: shop1 (HTTP 200)');
reset_calls();
$reseller = array_merge($service, array('configoption3' => 'on', 'domain' => ''));
check('reseller without domain', indianscloud_CreateAccount($reseller) === 'success' && last_call()['body']['acl'] === 'reseller');
check('domain required for user', strpos(indianscloud_CreateAccount(array_merge($service, array('domain' => ''))), 'needs a domain') !== false);
check('generated username', preg_match('/^shopexam\d{3}$/', indianscloud_panel_username('', 'shop.example.com')) === 1);
$withOption = array_merge($service, array('configoptions' => array('Package' => 'Gold')));
reset_calls();
indianscloud_CreateAccount($withOption);
check('configurable option overrides package', last_call()['body']['package'] === 'Gold');

// lifecycle
reset_calls();
check('suspend', indianscloud_SuspendAccount(array_merge($service, array('suspendreason' => 'Overdue; $5'))) === 'success');
check('suspend reason cleaned', strpos(last_call()['body']['reason'], ';') === false && strpos(last_call()['body']['reason'], '$') === false);
check('unsuspend', indianscloud_UnsuspendAccount($service) === 'success' && substr(last_call()['url'], -9) === 'unsuspend');
check('terminate', indianscloud_TerminateAccount($service) === 'success' && substr(last_call()['url'], -9) === 'terminate');
check('change password', indianscloud_ChangePassword($service) === 'success' && base64_decode(last_call()['body']['passwordB64']) === 'Pa$$w0rd;|x');
check('change package', indianscloud_ChangePackage($service) === 'success' && last_call()['body']['package'] === 'Starter');
reset_calls(array('<html>502</html>'));
check('non-json response', strpos(indianscloud_SuspendAccount($service), 'unexpected response') !== false);

// SSO
reset_calls(array(array('status' => 1, 'url' => 'https://panel.example.com:8090/api/v2/sso/redeem?ticket=abc')));
$r = indianscloud_ServiceSingleSignOn($service);
check('service sso', $r['success'] === true && strpos($r['redirectTo'], 'ticket=abc') !== false && last_call()['body']['username'] === 'Shop1');
reset_calls(array(array('status' => 1, 'url' => 'https://panel.example.com:8090/api/v2/sso/redeem?ticket=def')));
$r = indianscloud_AdminSingleSignOn($server);
check('admin sso', $r['success'] === true && last_call()['body'] === array());
reset_calls(array(array('status' => 0, 'error_message' => 'This account is suspended.')));
$r = indianscloud_ServiceSingleSignOn($service);
check('sso error', $r['success'] === false && strpos($r['errorMsg'], 'suspended') !== false);

// UsageUpdate
$written = null;
$GLOBALS['indianscloud_usage_writer'] = function ($serverId, $rows) use (&$written) { $written = array($serverId, $rows); };
reset_calls(array(array('status' => 1, 'usage' => array(array('username' => 'shop1', 'state' => 'ACTIVE',
    'sites' => array(array('domain' => 'shop.example')),
    'total' => array('disk_mb' => 130.6, 'disk_limit_mb' => 2000, 'bandwidth_mb' => 305.2, 'bandwidth_limit_mb' => 0))))));
check('usage update', indianscloud_UsageUpdate($server) === 'success');
check('usage rows', $written[0] === 3 && $written[1]['shop1']['diskusage'] === 131 && $written[1]['shop1']['bwusage'] === 305
      && $written[1]['shop1']['disklimit'] === 2000);

// ClientArea
reset_calls(array(array('status' => 1, 'usage' => array(array('username' => 'shop1', 'state' => 'ACTIVE', 'sites' => array(),
    'total' => array('disk_mb' => 1, 'disk_limit_mb' => 0, 'bandwidth_mb' => 2, 'bandwidth_limit_mb' => 0))))));
$r = indianscloud_ClientArea($service);
check('client area', $r['tabOverviewReplacementTemplate'] === 'templates/overview.tpl' && $r['templateVariables']['usage']['total']['bandwidth_mb'] === 2);
check('client area url', $r['templateVariables']['panelUrl'] === 'https://panel.example.com:8090/');

echo ($failures === 0 ? "OK" : "FAILED") . " ($count checks, $failures failures)\n";
exit($failures === 0 ? 0 : 1);
