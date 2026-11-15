<?php
/*
 * CyberPanel sign-on for MailWatch (installed into public/mailwatch/mailscanner/).
 * Accepts a single-use ticket written by the panel (plogical/mailwatchSSO.py) for a signed-in
 * panel administrator and opens a MailWatch session for the mapped MailWatch user, setting the
 * same session values as checklogin.php does after a password login.
 */
require_once __DIR__ . '/functions.php';
disableBrowserCache();

const CP_SSO_DIR = '/var/lib/cp-mailwatch-sso';

function cp_sso_fail()
{
    header('Location: login.php?error=baduser');
    exit;
}

$token = isset($_POST['cp_sso']) ? (string)$_POST['cp_sso'] : '';
if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
    cp_sso_fail();
}
$path = CP_SSO_DIR . '/' . hash('sha256', $token) . '.json';
$claimed = $path . '.claimed-' . bin2hex(random_bytes(4));
if (!@rename($path, $claimed)) {   // atomic: a ticket works exactly once
    cp_sso_fail();
}
$record = json_decode((string)@file_get_contents($claimed), true);
@unlink($claimed);
if (!is_array($record) || !isset($record['user'], $record['expires']) || $record['expires'] < time()) {
    cp_sso_fail();
}
$myusername = (string)$record['user'];
if (!preg_match('/^[A-Za-z0-9._@-]{1,191}$/', $myusername)) {
    cp_sso_fail();
}

$link = dbconn();
$safe_user = $link->real_escape_string($myusername);
$result = dbquery("SELECT fullname, type FROM users WHERE username = '$safe_user'");
if (!$result || $result->num_rows !== 1) {
    cp_sso_fail();
}
$row = $result->fetch_assoc();
if ($row['type'] !== 'A') {   // the panel signs in administrators only
    cp_sso_fail();
}

$filter = [$myusername];
$filters = dbquery("SELECT filter FROM user_filters WHERE username = '$safe_user' AND active = 'Y'");
while ($filters && ($f = $filters->fetch_array())) {
    $filter[] = $f['filter'];
}

session_regenerate_id(true);
$_SESSION['user_ldap'] = false;
$_SESSION['user_imap'] = false;
$_SESSION['myusername'] = $myusername;
$_SESSION['fullname'] = $row['fullname'];
$_SESSION['user_type'] = 'A';
$_SESSION['domain'] = '';
$_SESSION['global_filter'] = '(' . address_filter_sql($filter, 'A') . ')';
$_SESSION['global_list'] = '1=1';
$_SESSION['global_array'] = $filter;
$_SESSION['token'] = generateToken();
$_SESSION['formtoken'] = generateToken();
updateLoginExpiry($myusername);
audit_log('Signed in from CyberPanel as panel user ' . preg_replace('/[^A-Za-z0-9._@-]/', '', (string)($record['panel_user'] ?? '')), $myusername);
header('Location: index.php');
