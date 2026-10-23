(function () {
    'use strict';
    var root = document.getElementById('ua-htaccess');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var current = null;
    var BADGE = {translated: 'pass', native: 'pass', partial: 'warn', ignored: 'info', unsupported: 'warn', refused: 'fail'};

    function load() {
        return api('overview', {}).then(function (d) {
            var r = d.result;
            $('ht-sites').innerHTML = '<table class="ua-table"><thead><tr><th>Site</th><th>Translation</th><th>Brute-force guard</th><th></th></tr></thead><tbody>' +
                r.sites.map(function (s) {
                    return '<tr><td><strong>' + esc(s.domain) + '</strong></td><td>' + (s.enabled ? '<span class="ua-badge ua-badge-pass">on</span> <span class="ua-muted">applied ' +
                        esc(new Date(s.applied * 1000).toLocaleString()) + '</span>' : '<span class="ua-badge ua-badge-info">off</span>') + '</td><td>' +
                        (s.bruteforce ? '<span class="ua-badge ua-badge-pass">on</span>' : '') + '</td><td><button class="ua-btn ua-btn-secondary ht-preview" data-domain="' +
                        esc(s.domain) + '">Preview</button></td></tr>';
                }).join('') + '</tbody></table>';
            $('ht-blocks').innerHTML = r.blocks.length ? '<table class="ua-table"><tbody>' + r.blocks.slice().reverse().map(function (b) {
                return '<tr><td>' + esc(new Date(b.at * 1000).toLocaleString()) + '</td><td>' + esc(b.ip) + '</td><td>' + esc(b.domain) + '</td><td>' +
                    esc(b.attempts) + ' attempts</td><td>' + esc(b.action) + (b.via ? ' via ' + esc(b.via) : '') +
                    (b.until ? ' until ' + esc(new Date(b.until * 1000).toLocaleTimeString()) : '') + (b.error ? ' <span class="ua-badge ua-badge-fail">' + esc(b.error) + '</span>' : '') + '</td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No blocks in the last 24 hours.</p>';
        }).catch(function (e) { UA.showError($('ht-sites'), e); });
    }

    function managed(text) {
        var start = text.indexOf('# BEGIN cp-ua-htaccess'), end = text.indexOf('# END cp-ua-htaccess');
        return start >= 0 ? text.slice(start, end + '# END cp-ua-htaccess'.length) : '(nothing to add)';
    }

    function preview(domain) {
        current = domain;
        $('ht-preview').style.display = 'block';
        $('ht-preview-title').textContent = domain;
        $('ht-out').innerHTML = '<p class="ua-muted">Reading .htaccess files…</p>';
        return api('preview', {domain: domain}).then(function (d) {
            var p = d.result;
            $('ht-out').innerHTML = '<p>' + esc(p.files.length) + ' .htaccess file(s): ' + esc(p.files.map(function (f) { return '/' + f; }).join(', ') || 'none') +
                (p.changed ? '' : ' · <span class="ua-badge ua-badge-pass">already up to date</span>') + '</p>' +
                (p.conflicts.length ? '<div class="ua-alert">Skipped because vhost.conf already defines: ' + esc(p.conflicts.join(', ')) + '</div>' : '');
            $('ht-report').innerHTML = p.report.length ? '<table class="ua-table"><tbody>' + p.report.map(function (r) {
                return '<tr><td><span class="ua-badge ua-badge-' + (BADGE[r.status] || 'info') + '">' + esc(r.status) + '</span></td><td><code>' + esc(r.file) + ':' + esc(r.line) +
                    '</code></td><td><code>' + esc(r.directive) + '</code></td><td class="ua-muted">' + esc(r.detail) + '</td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No directives found.</p>';
            $('ht-config').textContent = managed(p.vhost_after);
            $('ht-redirects').innerHTML = p.htaccess_after.indexOf('# BEGIN cp-ua redirects') === 0
                ? '<h2 style="margin-top:16px">Added to the top of .htaccess</h2><div class="ua-pre">' + esc(p.htaccess_after.split('# END cp-ua redirects')[0] + '# END cp-ua redirects') + '</div>' : '';
        }).catch(function (e) { UA.showError($('ht-out'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.ht-preview');
        if (t) { preview(t.dataset.domain); $('ht-preview').scrollIntoView({behavior: 'smooth'}); }
    });
    function act(name, button, text) {
        if (!window.confirm(text)) { return; }
        UA.busy(button, true);
        api(name, {domain: current}).then(function (d) {
            $('ht-out').insertAdjacentHTML('afterbegin', '<p><span class="ua-badge ua-badge-pass">Done</span> ' +
                (d.result.applied.length ? 'Applied and OpenLiteSpeed restarted; the site answered normally.' : 'Nothing needed changing.') + '</p>');
            load(); preview(current);
        }).catch(function (e) { UA.showError($('ht-out'), e); }).then(function () { UA.busy(button, false); });
    }
    $('ht-enable').addEventListener('click', function () { act('enable', this, 'Apply the translation for ' + current + ' and restart OpenLiteSpeed?'); });
    $('ht-disable').addEventListener('click', function () { act('disable', this, 'Remove the translated configuration for ' + current + '?'); });

    load();
})();
