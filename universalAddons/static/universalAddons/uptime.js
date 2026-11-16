(function () {
    'use strict';
    var root = document.getElementById('ua-uptime');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var admin = root.dataset.admin === '1';
    var monitors = [], editing = null;

    function pct(v) { return v === null || v === undefined ? '&ndash;' : esc(v) + '%'; }
    function badge(state) {
        var cls = state === 'up' ? 'pass' : (state === 'down' ? 'fail' : 'info');
        return '<span class="ua-badge ua-badge-' + cls + '">' + esc(state) + '</span>';
    }
    function when(ts) { return ts ? esc(new Date(ts * 1000).toLocaleString()) : '&ndash;'; }

    function showKind() {
        var kind = $('up-kind').value;
        Array.prototype.forEach.call(root.querySelectorAll('[data-kind]'), function (el) {
            el.style.display = el.dataset.kind === kind ? '' : 'none';
        });
    }

    function render(r) {
        monitors = r.monitors;
        $('up-count').textContent = r.limit === null ? '' : '(' + r.count + ' / ' + r.limit + ')';
        $('up-sites').innerHTML = r.sites.map(function (s) { return '<option value="https://' + esc(s) + '/">'; }).join('');
        $('up-list').innerHTML = monitors.length ? '<table class="ua-table"><thead><tr><th>Monitor</th>' + (admin ? '<th>Owner</th>' : '') +
            '<th>State</th><th>24 h</th><th>7 d</th><th>30 d</th><th>Response, last 24 h</th><th>Certificate</th><th></th></tr></thead><tbody>' +
            monitors.map(function (m) {
                return '<tr><td><strong>' + esc(m.name) + '</strong><div class="ua-muted">' + esc(m.target_label) + ' &middot; every ' + esc(m.interval) + ' min' +
                    (m.enabled ? '' : ' &middot; paused') + '</div>' + (m.last_error ? '<div class="ua-muted">' + esc(m.last_error) + '</div>' : '') + '</td>' +
                    (admin ? '<td>' + esc(m.owner) + '</td>' : '') +
                    '<td>' + badge(m.state) + '</td><td>' + pct(m.uptime_24h) + '</td><td>' + pct(m.uptime_7d) + '</td><td>' + pct(m.uptime_30d) + '</td>' +
                    '<td>' + m.sparkline + '<div class="ua-muted">' + (m.avg_ms === null ? '' : 'avg ' + esc(m.avg_ms) + ' ms') + '</div></td>' +
                    '<td>' + (m.cert_days === null ? '&ndash;' : esc(m.cert_days) + ' days') + '</td>' +
                    '<td style="white-space:nowrap"><button class="ua-btn ua-btn-secondary" data-detail="' + m.id + '">History</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-check="' + m.id + '">Check now</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-edit="' + m.id + '">Edit</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-del="' + m.id + '">Delete</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">No monitors yet. Add one below.</p>';
    }

    function load() {
        api('overview', {}).then(function (d) { render(d.result); }).catch(function (e) { UA.showError($('up-list'), e); });
    }

    function reset() {
        editing = null;
        ['up-name', 'up-url', 'up-keyword', 'up-host', 'up-port'].forEach(function (id) { $(id).value = ''; });
        $('up-kind').value = 'http';
        $('up-interval').value = '5';
        $('up-enabled').checked = true;
        $('up-cancel').style.display = 'none';
        $('up-form-title').textContent = 'Add a monitor';
        showKind();
    }

    function edit(id) {
        var m = monitors.filter(function (x) { return x.id === id; })[0];
        if (!m) { return; }
        reset();
        editing = id;
        $('up-kind').value = m.kind;
        $('up-name').value = m.name;
        $('up-interval').value = String(m.interval);
        $('up-enabled').checked = !!m.enabled;
        if (m.kind === 'http') {
            $('up-url').value = m.target;
            $('up-keyword').value = m.keyword;
            $('up-mode').value = m.keyword_mode || 'present';
        } else {
            $('up-host').value = m.target;
            $('up-port').value = m.port;
        }
        $('up-cancel').style.display = '';
        $('up-form-title').textContent = 'Edit ' + m.name;
        showKind();
    }

    function detail(id) {
        api('detail', {id: id}).then(function (d) {
            var m = d.result;
            $('up-detail').style.display = 'block';
            $('up-detail-title').textContent = m.name + ' (' + m.target_label + ')';
            $('up-detail-out').innerHTML = '<p>' + badge(m.state) + ' Uptime 24 h ' + pct(m.uptime_24h) + ', 7 d ' + pct(m.uptime_7d) + ', 30 d ' + pct(m.uptime_30d) + '</p>' +
                '<div>' + m.sparkline + '</div><h3>Incidents (30 days)</h3>' +
                (m.incidents.length ? '<table class="ua-table"><thead><tr><th>Started</th><th>Ended</th><th>Duration</th><th>Reason</th></tr></thead><tbody>' +
                    m.incidents.map(function (i) {
                        return '<tr><td>' + when(i.started) + '</td><td>' + (i.ended ? when(i.ended) : '<span class="ua-badge ua-badge-fail">ongoing</span>') +
                            '</td><td>' + esc(i.minutes) + ' min</td><td>' + esc(i.reason) + '</td></tr>';
                    }).join('') + '</tbody></table>' : '<p class="ua-muted">No incidents.</p>') +
                '<h3>Latest checks</h3><p class="ua-muted">' + m.recent.map(function (r) {
                    return '<span title="' + when(r.ts) + '">' + (r.ok ? '&#9679;' : '<span style="color:#dc2626">&#9679;</span>') + '</span>';
                }).join(' ') + '</p>';
            $('up-detail').scrollIntoView({behavior: 'smooth'});
        }).catch(function (e) { window.alert(e.message); });
    }

    $('up-kind').onchange = showKind;
    $('up-cancel').onclick = reset;
    $('up-save').onclick = function () {
        var kind = $('up-kind').value, button = this;
        var monitor = {kind: kind, name: $('up-name').value, interval: parseInt($('up-interval').value, 10), enabled: $('up-enabled').checked};
        if (kind === 'http') {
            monitor.url = $('up-url').value;
            monitor.keyword = $('up-keyword').value;
            monitor.keyword_mode = monitor.keyword ? $('up-mode').value : '';
        } else {
            monitor.host = $('up-host').value;
            monitor.port = parseInt($('up-port').value, 10);
        }
        var body = {monitor: monitor};
        if (editing) { body.id = editing; }
        UA.busy(button, true);
        api('save', body).then(function () { $('up-note').textContent = 'Saved.'; reset(); load(); })
            .catch(function (e) { $('up-note').textContent = e.message; })
            .then(function () { UA.busy(button, false); });
    };
    $('up-list').onclick = function (event) {
        var t = event.target, id;
        if (t.dataset.detail) { detail(parseInt(t.dataset.detail, 10)); }
        if (t.dataset.edit) { edit(parseInt(t.dataset.edit, 10)); }
        if (t.dataset.check) {
            id = parseInt(t.dataset.check, 10);
            UA.busy(t, true);
            api('check_now', {id: id}).then(function (d) {
                window.alert(d.result.ok ? 'OK (' + d.result.ms + ' ms)' : 'Failed: ' + d.result.error);
                load();
            }).catch(function (e) { window.alert(e.message); }).then(function () { UA.busy(t, false); });
        }
        if (t.dataset.del && window.confirm('Delete this monitor and its history?')) {
            api('delete', {id: parseInt(t.dataset.del, 10)}).then(load).catch(function (e) { window.alert(e.message); });
        }
    };
    if (root.dataset.site) { $('up-url').value = 'https://' + root.dataset.site + '/'; $('up-name').value = root.dataset.site; }
    showKind();
    load();
})();
