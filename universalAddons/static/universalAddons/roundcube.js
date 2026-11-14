(function () {
    'use strict';
    var root = document.getElementById('ua-roundcube');
    if (!root || !document.getElementById('rc-status')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {};

    function badge(ok, yes, no) {
        return '<span class="ua-badge ua-badge-' + (ok ? 'pass' : 'fail') + '">' + esc(ok ? yes : no) + '</span>';
    }

    function loadStatus() {
        return UA.retry(function () { return api('overview', {}); }).then(function (d) {
            var s = state = d.result, rows = [];
            if (!s.installed) {
                $('rc-status').innerHTML = '<p>Not installed. Roundcube ' + esc(s.pinned) + ' will be installed to /usr/local/cp-roundcube.</p>';
            } else {
                rows.push(['Version', esc(s.version)]);
                rows.push(['Database', badge(s.db && s.db.ok, 'OK', 'Problem') + ' ' + esc(s.db ? s.db.detail : '')]);
                rows.push(['Site', esc(s.site || 'none') + (s.php_handler ? ' · PHP handler ' + esc(s.php_handler) : '')]);
                rows.push(['Served', badge(s.enabled && s.block_present, 'yes', 'no') +
                    (s.url && s.enabled ? ' <a href="' + esc(s.url) + '" target="_blank" rel="noopener">' + esc(s.url) + '</a>' : '')]);
                if (s.site_problem) { rows.push(['Problem', esc(s.site_problem)]); }
                $('rc-status').innerHTML = '<table class="ua-table"><tbody>' + rows.map(function (r) {
                    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
                }).join('') + '</tbody></table>';
                if (s.site) { $('rc-site').value = s.site; }
            }
            $('rc-manage').style.display = s.installed ? 'block' : 'none';
            $('rc-install').style.display = 'none';
            $('rc-enable').style.display = 'none';
        }).catch(function (e) { UA.showError($('rc-status'), e); });
    }

    function preflight() {
        var site = $('rc-site').value;
        if (!site) { UA.showError($('rc-preflight'), new Error('Choose a site.')); return; }
        var button = $('rc-check');
        UA.busy(button, true);
        api('preflight', {site: site}).then(function (d) {
            var p = d.result;
            $('rc-preflight').innerHTML = '<table class="ua-table"><tbody>' + p.checks.map(function (c) {
                return '<tr><td>' + badge(c.ok, 'OK', 'No') + '</td><td>' + esc(c.detail) + '</td></tr>';
            }).join('') + '</tbody></table>' + (p.ssl ? '' : '<div class="ua-alert">This site has no SSL certificate; mailbox passwords would cross the network unencrypted.</div>');
            $('rc-install').style.display = p.ready && !state.installed ? '' : 'none';
            $('rc-enable').style.display = p.ready && state.installed ? '' : 'none';
        }).catch(function (e) { UA.showError($('rc-preflight'), e); }).then(function () { UA.busy(button, false); });
    }

    function watch(jobId) {
        $('rc-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('rc-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' + (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) +
                    '">' + esc(j.state) + '</span></p>' + (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 4000); } else { loadStatus(); }
            }).catch(function (e) { UA.showError($('rc-job-out'), e); });
        })();
    }

    function action(button, name, body, then) {
        UA.busy(button, true);
        // Starting jobs is not retried (a lost reply must not start a second job); the rest is idempotent.
        var request = function () { return api(name, body); };
        return (name === 'install' || name === 'enable' ? request() : UA.retry(request)).then(then).catch(function (e) { UA.showError($('rc-out'), e); })
            .then(function () { UA.busy(button, false); });
    }

    $('rc-check').addEventListener('click', preflight);
    $('rc-install').addEventListener('click', function () {
        action(this, 'install', {site: $('rc-site').value}, function (d) { watch(d.result.job_id); });
    });
    $('rc-enable').addEventListener('click', function () {
        action(this, 'enable', {site: $('rc-site').value}, function (d) { $('rc-out').innerHTML = ''; watch(d.result.job_id); });
    });
    $('rc-disable').addEventListener('click', function () {
        if (!window.confirm('Remove Roundcube from the site\'s vhost? Users can no longer open it until you serve it again.')) { return; }
        action(this, 'disable', {}, loadStatus);
    });
    $('rc-upgrade').addEventListener('click', function () {
        action(this, 'upgrade', {}, function (d) {
            var u = d.result;
            $('rc-upgrade-out').innerHTML = '<p>Installed ' + esc(u.installed || 'none') + ', latest 1.6 release ' + esc(u.latest || 'unknown') + ' ' +
                badge(!u.update_available, 'up to date', 'update available') +
                (u.update_available && u.release_url ? ' <a href="' + esc(u.release_url) + '" target="_blank" rel="noopener">release notes</a>' : '') +
                '. Upgrades are not applied automatically.</p>';
        });
    });
    $('rc-uninstall').addEventListener('click', function () {
        var drop = $('rc-drop').checked, confirmName = $('rc-confirm').value.trim();
        if (drop && confirmName !== root.dataset.db) {
            UA.showError($('rc-out'), new Error('Type ' + root.dataset.db + ' to confirm dropping the database.'));
            return;
        }
        if (!window.confirm(drop ? 'Uninstall Roundcube and DROP its database? This cannot be undone.' : 'Uninstall Roundcube (keeping its database)?')) { return; }
        action(this, 'uninstall', {dropDatabase: drop, confirmName: drop ? confirmName : ''}, loadStatus);
    });
    loadStatus();
})();
