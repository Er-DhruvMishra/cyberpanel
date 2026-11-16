'use strict';
// Incremental (v2) Google Drive setup: no client credentials in the browser,
// only Google's own authorisation URL is opened.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/IncBackups/IncBackups.js', 'utf8');
const template = fs.readFileSync(__dirname + '/templates/IncBackups/ConfigureV2Backup.html', 'utf8');
assert.match(template, /block module_scripts/);
assert.match(template, /IncBackups\/IncBackups\.js.*gdrive-own-client-3/);
assert.match(template, /ng-disabled="!gdriveAvailable \|\| gdriveSetupPending"/);
assert.ok(!template.includes('ng-model="client_secret"'), 'no client secret field');
assert.ok(!template.includes('ng-change="selectwebsite()"'), 'no undefined website-change handler');
const start = source.indexOf("app.controller('ConfigureV2Backup'");
const end = source.indexOf("app.controller('ScheduleV2Backup'", start);
assert.ok(start > 0 && end > start);
const ORIGIN = 'https://panel.example.test:8090';
const CALLBACK = ORIGIN + '/IncrementalBackups/ConfigureV2BackupSetup';
function google(extra) {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', 'synthetic.apps.googleusercontent.com');
    url.searchParams.set('redirect_uri', CALLBACK);
    url.searchParams.set('state', 's'.repeat(43));
    if (extra) extra(url);
    return url.href;
}
function fixture(blocked = false, enabled = true) {
    const calls = [], notices = [];
    const popup = {opener: {}, location: {}, closed: false, close() { this.closed = true; }};
    let success, failure, capabilitySuccess, capabilityFailure;
    const scope = {selwebsite: 'owned.example', accountName: 'qa-drive'};
    vm.runInNewContext(source.slice(start, end), {
        app: {controller(name, factory) {
            assert.equal(name, 'ConfigureV2Backup');
            factory(scope, {
                get(url) {assert.equal(url, '/IncrementalBackups/GDriveSetupStatus');
                    return {then(ok,bad) {capabilitySuccess=ok;capabilityFailure=bad;}};},
                post(...args) { calls.push(args); return {then(ok, bad) { success = ok; failure = bad; }}; }
            }, {});
        }},
        window: {open(url) {assert.equal(url, 'about:blank'); return blocked ? null : popup;},
                 location: {origin: ORIGIN}},
        getCookie(name) { assert.equal(name, 'csrftoken'); return 'synthetic-csrf'; },
        PNotify: function(options) { notices.push(options); }, URL,
    });
    if (enabled !== null) capabilitySuccess({data:{status:1,enabled,reason:'Admin must save a client'}});
    return {scope, calls, popup, notices, success(data) {success({data});}, failure(data) {failure({data});},
        status(data) {capabilitySuccess({data});}, statusFailure() {capabilityFailure();}};
}
for (const enabled of [false, null]) {
    const disabled = fixture(false, enabled);
    disabled.scope.setupAccount();
    assert.equal(disabled.calls.length, 0, 'disabled or unchecked setup never starts');
}
assert.equal(fixture(false, false).scope.gdriveUnavailableReason, 'Admin must save a client');
for (const data of [{status:1,enabled:'true'},{status:0,enabled:true},null]) {
    const disabled = fixture(false,null); disabled.status(data); disabled.scope.setupAccount();
    assert.equal(disabled.calls.length,0,'malformed capability fails closed');
}
const unavailable = fixture(false,null); unavailable.statusFailure(); unavailable.scope.setupAccount();
assert.equal(unavailable.calls.length,0);
let f = fixture();
f.scope.setupAccount();
f.scope.setupAccount();
assert.equal(f.calls.length, 1, 'double click suppressed');
assert.equal(f.calls[0][0], '/IncrementalBackups/BeginV2GDriveSetup');
assert.deepEqual(Object.keys(f.calls[0][1]).sort(), ['Selectedwebsite', 'accountName']);
assert.equal(f.calls[0][2].headers['X-CSRFToken'], 'synthetic-csrf');
assert.equal(f.popup.opener, null);
f.success({status: 1, authorization_url: google()});
assert.equal(f.popup.location.href, google());
assert.equal(f.scope.gdriveSetupPending, false);
for (const value of [undefined, {status: 0, error_message: 'x'},
    {status: 1, authorization_url: google().replace('https:', 'http:')},
    {status: 1, authorization_url: google().replace('accounts.google.com', 'accounts.google.com.evil.test')},
    {status: 1, authorization_url: google().replace('/o/oauth2/v2/auth', '/gDrive/v2/start')},
    {status: 1, authorization_url: google(u => u.searchParams.set('redirect_uri', 'https://evil.test/cb'))},
    {status: 1, authorization_url: google(u => { u.username = 'user'; })},
    {status: 1, authorization_url: 'https://platform.cyberpersons.com/gDrive/v2/start?handoff=' + 'a'.repeat(43)}]) {
    f = fixture(); f.scope.setupAccount(); f.success(value);
    assert.equal(f.popup.closed, true);
    assert.equal(f.scope.gdriveSetupPending, false);
    assert.equal(f.notices.length, 1);
}
f = fixture(); f.scope.setupAccount(); f.failure({status: 0, error_message: 'Use 1-50 letters'});
assert.equal(f.popup.closed, true);
assert.equal(f.notices[0].text, 'Use 1-50 letters');
f.scope.setupAccount();
assert.equal(f.calls.length, 2, 'retry enabled after failure');
f = fixture(true); f.scope.setupAccount();
assert.equal(f.calls.length, 0, 'blocked popup must not start setup');
assert.equal(f.notices.length, 1);
console.log('OK v2 Drive setup: no client fields, CSRF header, popup isolation, duplicate guard, Google URL validation, errors and retry');
