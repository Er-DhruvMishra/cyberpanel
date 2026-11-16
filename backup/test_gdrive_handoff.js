'use strict';
// Normal Google Drive backups page: admin client form (secret never shown) and
// the "Connect Google Drive" flow that opens only Google's authorisation URL.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const ORIGIN='https://panel.example.test:8090';
const template=fs.readFileSync(__dirname+'/templates/backup/googleDrive.html','utf8');
assert.match(template,/gdrive-own-client-4/);
assert.match(template,/Connect Google Drive/);
assert.match(template,/type="password" autocomplete="new-password"/);
// Regression: Reconnect was rendered disabled (ng-disabled="!gdriveSetupEnabled ...") when the panel had
// no Google OAuth client, so clicking it did nothing and the reason was only inside the Connect modal.
assert.match(template,/ng-click="reconnectAccount\(\)" class="btn-secondary"\s+ng-disabled="gdriveSetupPending"/);
assert.match(template,/selectedAccount && !gdriveSetupEnabled[^>]*>\s*<span ng-bind="gdriveSetupReason">/);
assert.match(template,/addons\/destinations|ua-destinations/,'new connections go to Backup destinations');
assert.match(template,/drive\.file/);
assert.ok(!template.includes('ng-model="client_secret"'),'no per-account secret field');
for(const file of ['/static/backup/backup.js','/../static/backup/backup.js']){
const source=fs.readFileSync(__dirname+file,'utf8');
assert.ok(!source.includes('platform.cyberpersons.com/gDrive'),'vendor link removed in '+file);
const start=source.indexOf("app.controller('googleDrive'");
const end=source.indexOf('$scope.currentPage',start);
function google(extra){const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.searchParams.set('redirect_uri',ORIGIN+'/backup/gDriveSetup');u.searchParams.set('state','s'.repeat(43));
  if(extra)extra(u);return u.href;}
function fixture(enabled=true,blocked=false,admin=false){
  const calls=[],gets=[],notices=[],scope={accountName:'new'};
  let ok,bad;
  const popup={opener:{},location:{},closed:false,close(){this.closed=true;}};
  const replies={'/backup/GDriveSetupStatus':{status:1,enabled,is_admin:admin,reason:'Admin must save a client',
      accounts:[{name:'old',connection:'vendor',reconnect:false},{name:'mine',connection:'panel',reconnect:true}]},
    '/backup/gDriveOAuthClient':{status:1,configured:true,client_id:'x.apps.googleusercontent.com',client_secret:'set',
      redirect_uris:[ORIGIN+'/backup/gDriveSetup']}};
  vm.runInNewContext(source.slice(start,end)+'});',{
    app:{controller(name,fn){fn(scope,{get(url){gets.push(url);return{then(success){success({data:replies[url]});}};},
      post(...args){calls.push(args);return{then(a,b){ok=a;bad=b;}};}});}},
    window:{open(url){assert.equal(url,'about:blank');return blocked?null:popup;},location:{origin:ORIGIN}},URL,Array,
    getCookie(){return 'synthetic-csrf';},PNotify:function(options){notices.push(options);}
  });
  return {scope,calls,gets,popup,notices,success(data){ok({data});},fail(data){bad({data});}};
}
let f=fixture(false);f.scope.setupAccount();assert.equal(f.calls.length,0);
assert.equal(f.scope.gdriveSetupReason,'Admin must save a client');
assert.deepEqual(f.gets,['/backup/GDriveSetupStatus'],'non-admin never loads client settings');
f=fixture(false);f.scope.selectedAccount='old';f.scope.reconnectAccount();
assert.equal(f.calls.length,0,'no request without a client');
assert.equal(f.notices.length,1,'Reconnect explains why it cannot start');
assert.match(f.notices[0].text,/Admin must save a client/);
f=fixture(false,false,true);f.scope.selectedAccount='old';f.scope.reconnectAccount();
assert.match(f.notices[0].text,/Google OAuth client/,'admins are pointed at the client form');
f=fixture();
assert.equal(f.scope.accountState('old').connection,'vendor');
assert.equal(f.scope.accountState('mine').reconnect,true);
f.scope.setupAccount();f.scope.setupAccount();assert.equal(f.calls.length,1);
assert.equal(f.calls[0][0],'/backup/BeginGDriveSetup');
assert.equal(JSON.stringify(f.calls[0][1]),JSON.stringify({accountName:'new'}));
assert.equal(f.calls[0][2].headers['X-CSRFToken'],'synthetic-csrf');
assert.equal(f.popup.opener,null);
f.success({status:1,authorization_url:google()});
assert.equal(f.popup.location.href,google());
f=fixture();f.scope.selectedAccount='mine';f.scope.reconnectAccount();
assert.equal(JSON.stringify(f.calls[0][1]),JSON.stringify({accountName:'mine'}),'reconnect reuses the selected account');
for(const authorization_url of [google().replace('https:','http:'),google(u=>u.hash='x'),
 google(u=>u.searchParams.set('redirect_uri','https://evil.test/backup/gDriveSetup')),
 google().replace('accounts.google.com','accounts.google.com.evil.test'),
 'https://platform.cyberpersons.com/gDrive/v2/start?handoff='+'a'.repeat(43)]){
 f=fixture();f.scope.setupAccount();f.success({status:1,authorization_url});
 assert.equal(f.popup.closed,true);
}
f=fixture();f.scope.setupAccount();f.fail({status:0,error_message:'This account name is already in use.'});
assert.equal(f.notices[0].text,'This account name is already in use.');
f.scope.setupAccount();assert.equal(f.calls.length,2);
f=fixture(true,true);f.scope.setupAccount();assert.equal(f.calls.length,0);
// Admin client form: secret is sent once, cleared, and never read back.
f=fixture(true,false,true);
assert.deepEqual(f.gets,['/backup/GDriveSetupStatus','/backup/gDriveOAuthClient']);
assert.equal(f.scope.oauthClient.client_secret,'set');
assert.equal(f.scope.oauthClientSecret,'');
f.scope.oauthClientId='x.apps.googleusercontent.com';f.scope.oauthClientSecret='SYNTHETIC-SECRET';
f.scope.saveOAuthClient();
assert.equal(f.calls[0][0],'/backup/gDriveOAuthClient');
assert.equal(JSON.stringify(f.calls[0][1]),JSON.stringify({client_id:'x.apps.googleusercontent.com',client_secret:'SYNTHETIC-SECRET'}));
f.success({status:1,configured:true,client_id:'x.apps.googleusercontent.com',client_secret:'set'});
assert.equal(f.scope.oauthClientSecret,'');
f.scope.oauthClientSecret='SYNTHETIC-SECRET';f.scope.saveOAuthClient();f.fail({status:0,error_message:'bad'});
assert.equal(f.scope.oauthClientSecret,'','secret cleared on failure too');
f.scope.saveOAuthClient(true);assert.equal(JSON.stringify(f.calls[2][1]),JSON.stringify({clear:true}));
}
console.log('OK normal Drive page: admin client form, secret never read back, Google URL validation, reconnect, errors/retry');
