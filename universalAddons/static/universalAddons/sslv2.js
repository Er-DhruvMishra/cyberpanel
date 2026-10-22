(function () {
    'use strict';
    var root = document.getElementById('ua-sslv2');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var STATE = {ok: 'pass', expiring: 'warn', expired: 'fail', untrusted: 'fail', missing: 'info'};

    function toggleRows() {
        $('ssl-cf-row').style.display = $('ssl-provider').value === 'cloudflare' ? 'flex' : 'none';
        $('ssl-email-row').style.display = $('ssl-ca').value === 'zerossl' ? 'flex' : 'none';
    }
    $('ssl-provider').addEventListener('change', toggleRows);
    $('ssl-ca').addEventListener('change', toggleRows);

    function load() {
        return api('inventory', {}).then(function (d) {
            var rows = d.result.certificates;
            $('ssl-cf-saved').textContent = d.result.saved_cloudflare_token ? 'A Cloudflare token is already saved; leave empty to reuse it.' : '';
            $('ssl-list').innerHTML = rows.length ? '<table class="ua-table"><thead><tr><th>Domain</th><th>State</th>' +
                '<th>Names</th><th>Issuer</th><th>Expires</th><th>Renewal</th><th></th></tr></thead><tbody>' + rows.map(function (r) {
                    var c = r.certificate || {};
                    return '<tr><td><strong>' + esc(r.domain) + '</strong></td><td><span class="ua-badge ua-badge-' + STATE[r.state] + '">' +
                        esc(r.state) + '</span></td><td>' + esc((c.sans || []).join(', ')) + '</td><td>' + esc(c.issuer || '') + '</td><td>' +
                        (r.certificate ? esc(new Date(c.expires * 1000).toLocaleDateString()) + ' (' + esc(c.days_left) + ' d)' : '') +
                        '</td><td>' + esc(r.acme.challenge || '') + (r.acme.next_renewal ? '<div class="ua-fix">next ' + esc(r.acme.next_renewal) + '</div>' : '') +
                        '</td><td><button class="ua-btn ua-btn-secondary ssl-pick" data-domain="' + esc(r.domain) + '">Issue…</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No websites found.</p>';
        }).catch(function (e) { UA.showError($('ssl-list'), e); });
    }

    $('ssl-list').addEventListener('click', function (event) {
        var pick = event.target.closest('.ssl-pick');
        if (pick) { $('ssl-domain').value = pick.dataset.domain; window.scrollTo({top: 0, behavior: 'smooth'}); }
    });

    $('ssl-check').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('check', {domain: $('ssl-domain').value.trim(), provider: $('ssl-provider').value}).then(function (d) {
            var r = d.result;
            $('ssl-out').innerHTML = '<p><span class="ua-badge ua-badge-' + (r.ok ? 'pass' : 'fail') + '">' + (r.ok ? 'Ready' : 'Not ready') +
                '</span> Zone ' + esc(r.zone) + ': ' + esc(r.detail) + '</p>';
        }).catch(function (e) { UA.showError($('ssl-out'), e); }).then(function () { UA.busy(button, false); });
    });

    function watch(jobId) {
        (function poll() {
            api('job', {job: jobId}).then(function (d) {
                var j = d.result;
                $('ssl-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert" style="white-space:pre-wrap">' + esc(j.error) + '</div>' : '') +
                    '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 4000); } else { load(); }
            }).catch(function (e) { UA.showError($('ssl-out'), e); });
        })();
    }

    $('ssl-issue').addEventListener('click', function () {
        var button = this;
        var body = {
            domain: $('ssl-domain').value.trim(), provider: $('ssl-provider').value, wildcard: $('ssl-wildcard').checked,
            aliases: $('ssl-aliases').value.split(/\s+/).filter(Boolean), ca: $('ssl-ca').value, key: $('ssl-key').value,
            email: $('ssl-email').value.trim(), cfToken: $('ssl-cf-token').value.trim()
        };
        UA.busy(button, true);
        api('issue', body).then(function (d) { $('ssl-cf-token').value = ''; watch(d.result.job_id); })
            .catch(function (e) { UA.showError($('ssl-out'), e); }).then(function () { UA.busy(button, false); });
    });

    $('ssl-refresh').addEventListener('click', load);
    api('monitor', {}).then(function (d) { $('ssl-monitor').checked = d.result.enabled; }).catch(function () {});
    $('ssl-monitor').addEventListener('change', function () {
        var box = this;
        api('monitor', {enable: box.checked}).then(function (d) { box.checked = d.result.enabled; })
            .catch(function (e) { box.checked = !box.checked; UA.showError($('ssl-out'), e); });
    });

    toggleRows();
    load();
})();
