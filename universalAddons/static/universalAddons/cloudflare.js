/* Cloudflare add-on page. Talks only to the panel; the panel talks to Cloudflare. */
(function () {
    'use strict';
    var root = document.getElementById('ua-cloudflare');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var isAdmin = root.dataset.admin === '1';
    var st = {zone: null, zoneName: '', sites: [], links: {}, records: [], settings: null, serverIp: '', securityLevel: 'medium'};

    function source() { return isAdmin && $('cf-source') ? $('cf-source').value : 'own'; }
    function api(name, body) {
        body = body || {};
        body.source = source();
        if (st.zone && body.zone === undefined) { body.zone = st.zone; }
        return UA.api(base + name, body);
    }
    function note(target, text, kind) {
        target.innerHTML = '<p><span class="ua-badge ua-badge-' + (kind || 'pass') + '">' + (kind === 'fail' ? 'Error' : 'OK') + '</span> ' + esc(text) + '</p>';
    }
    function fail(target) { return function (e) { UA.showError(target || $('cf-out'), e); }; }
    function human(bytes) {
        var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
        bytes = Number(bytes || 0);
        while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i += 1; }
        return bytes.toFixed(i ? 1 : 0) + ' ' + units[i];
    }
    function num(n) { return Number(n || 0).toLocaleString(); }

    // ------------------------------------------------------------------ tokens
    function tokenText(t) {
        if (!t || !t.saved) { return '<span class="ua-badge ua-badge-warn">none</span> No token saved.'; }
        var v = t.verify || {}, ok = v.status === 'active';
        return '<span class="ua-badge ua-badge-' + (ok ? 'pass' : 'fail') + '">token saved</span> Cloudflare status: <strong>' +
            esc(v.status || 'unknown') + '</strong>' + (v.expires_on ? ', expires ' + esc(v.expires_on) : '') +
            (v.checked_at ? ' <span class="ua-muted">(checked ' + esc(new Date(v.checked_at * 1000).toLocaleString()) + ')</span>' : '');
    }
    function loadState() {
        return UA.api(base + 'state', {}).then(function (d) {
            var r = d.result;
            st.sites = r.sites || []; st.links = r.links || {}; st.serverIp = r.server_ip || '';
            $('cf-token-own').innerHTML = tokenText(r.token);
            if (r.server_token && $('cf-token-server')) { $('cf-token-server').innerHTML = tokenText(r.server_token); }
            $('cf-point-ip').textContent = st.serverIp ? 'This server: ' + st.serverIp : '';
        }).catch(fail($('cf-token-out')));
    }
    function tokenAction(name, src, input) {
        var body = {source: src};
        if (input) { body.input = {token: input.value.trim()}; }
        return UA.api(base + name, body).then(function () {
            if (input) { input.value = ''; }
            note($('cf-token-out'), name === 'token_forget' ? 'Token removed.' : 'Token checked with Cloudflare.');
            return loadState().then(loadZones);
        }).catch(fail($('cf-token-out')));
    }
    $('cf-token-save').onclick = function () { tokenAction('token_save', 'own', $('cf-token-input')); };
    $('cf-token-verify').onclick = function () { tokenAction('token_verify', 'own'); };
    $('cf-token-forget').onclick = function () { if (confirm('Forget your Cloudflare token?')) { tokenAction('token_forget', 'own'); } };
    if ($('cf-server-save')) {
        $('cf-server-save').onclick = function () { tokenAction('token_save', 'server', $('cf-server-input')); };
        $('cf-server-verify').onclick = function () { tokenAction('token_verify', 'server'); };
        $('cf-server-forget').onclick = function () { if (confirm('Forget the server-wide token?')) { tokenAction('token_forget', 'server'); } };
        $('cf-source').onchange = function () { st.zone = null; $('cf-zone').style.display = 'none'; loadZones(); };
    }

    // ------------------------------------------------------------------- zones
    function loadZones() {
        $('cf-zones').innerHTML = '<p class="ua-muted">Loading…</p>';
        return api('zones', {zone: null}).then(function (d) {
            var z = d.result.zones;
            $('cf-zones').innerHTML = z.length ? '<table class="ua-table"><thead><tr><th>Zone</th><th>Status</th><th>Plan</th><th>Linked site</th><th></th></tr></thead><tbody>' +
                z.map(function (x) {
                    return '<tr><td><strong>' + esc(x.name) + '</strong></td><td><span class="ua-badge ua-badge-' + (x.status === 'active' ? 'pass' : 'warn') + '">' + esc(x.status) +
                        '</span></td><td>' + esc(x.plan) + '</td><td>' + esc(x.site || '') + '</td><td><button type="button" class="ua-btn ua-btn-secondary" data-open="' + esc(x.id) +
                        '" data-name="' + esc(x.name) + '">Manage</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">This token can see no zones.</p>';
        }).catch(fail($('cf-zones')));
    }
    $('cf-zones-load').onclick = loadZones;
    $('cf-zones').onclick = function (e) {
        var b = e.target.closest('[data-open]');
        if (!b) { return; }
        st.zone = b.dataset.open; st.zoneName = b.dataset.name; st.settings = null;
        $('cf-zone').style.display = 'block';
        $('cf-zone-title').textContent = st.zoneName;
        showTab('overview');
    };

    // -------------------------------------------------------------------- tabs
    var loaders = {
        overview: loadOverview, dns: loadDns, cache: loadSettings, ssl: loadSettings, security: loadSecurity,
        analytics: loadAnalytics, speed: loadSettings, origin: function () {}, activity: loadAudit
    };
    function showTab(name) {
        $('cf-out').innerHTML = '';
        Array.prototype.forEach.call($('cf-tabs').children, function (b) { b.classList.toggle('active', b.dataset.tab === name); });
        Array.prototype.forEach.call(root.querySelectorAll('[data-pane]'), function (p) { p.classList.toggle('active', p.dataset.pane === name); });
        loaders[name]();
    }
    $('cf-tabs').onclick = function (e) { if (e.target.dataset.tab) { showTab(e.target.dataset.tab); } };

    function loadOverview() {
        $('cf-overview').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('overview').then(function (d) {
            var r = d.result, ns = r.ns || {};
            var nsBadge = ns.checked ? (ns.points_to_cloudflare ? '<span class="ua-badge ua-badge-pass">yes</span>' :
                '<span class="ua-badge ua-badge-fail">no</span> public NS: ' + esc((ns.public || []).join(', '))) : '<span class="ua-badge ua-badge-info">unknown</span> (lookup failed)';
            $('cf-overview').innerHTML = '<table class="ua-table">' +
                '<tr><th>Status</th><td>' + esc(r.status) + (r.paused ? ' (paused)' : '') + '</td></tr>' +
                '<tr><th>Plan</th><td>' + esc(r.plan) + '</td></tr>' +
                '<tr><th>Cloudflare name servers</th><td>' + esc((r.name_servers || []).join(', ')) + '</td></tr>' +
                '<tr><th>Previous name servers</th><td>' + esc((r.original_name_servers || []).join(', ')) + '</td></tr>' +
                '<tr><th>Domain points at Cloudflare</th><td>' + nsBadge + (r.status !== 'active' ? '<div class="ua-fix">Set these name servers at your domain registrar; Cloudflare activates the zone once they are live.</div>' : '') + '</td></tr></table>';
            var current = r.site || '';
            $('cf-link-site').innerHTML = '<option value="">(not linked)</option>' + st.sites.filter(function (s) {
                return s === st.zoneName || s.slice(-(st.zoneName.length + 1)) === '.' + st.zoneName;
            }).map(function (s) { return '<option' + (s === current ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join('');
        }).catch(fail($('cf-overview')));
    }
    $('cf-link-save').onclick = function () {
        api('link', {input: {site: $('cf-link-site').value}}).then(function (d) { st.links = d.result.links; note($('cf-out'), 'Link saved.'); }).catch(fail());
    };

    // --------------------------------------------------------------------- DNS
    function recordContent(r) {
        if (r.data && (r.type === 'SRV' || r.type === 'CAA')) {
            return r.type === 'SRV' ? [r.data.priority, r.data.weight, r.data.port, r.data.target].join(' ') : [r.data.flags, r.data.tag, '"' + r.data.value + '"'].join(' ');
        }
        return (r.priority !== undefined && r.priority !== null && r.type === 'MX' ? r.priority + ' ' : '') + (r.content || '');
    }
    function renderDns() {
        var f = $('cf-dns-filter').value.toLowerCase();
        var rows = st.records.filter(function (r) { return !f || (r.name + ' ' + r.type + ' ' + recordContent(r)).toLowerCase().indexOf(f) > -1; });
        $('cf-dns').innerHTML = '<table class="ua-table"><thead><tr><th>Type</th><th>Name</th><th>Content</th><th>TTL</th><th>Proxy</th><th></th></tr></thead><tbody>' +
            rows.map(function (r) {
                return '<tr><td>' + esc(r.type) + '</td><td>' + esc(r.name) + '</td><td style="word-break:break-all">' + esc(recordContent(r)) + '</td><td>' + (r.ttl === 1 ? 'Auto' : esc(r.ttl)) +
                    '</td><td>' + (r.proxiable ? '<label><input type="checkbox" data-proxy="' + esc(r.id) + '"' + (r.proxied ? ' checked' : '') + '> proxied</label>' : '<span class="ua-muted">DNS only</span>') +
                    '</td><td><button type="button" class="ua-btn ua-btn-secondary" data-edit="' + esc(r.id) + '">Edit</button> <button type="button" class="ua-btn ua-btn-secondary" data-del="' + esc(r.id) + '">Delete</button></td></tr>';
            }).join('') + '</tbody></table>';
    }
    function loadDns() {
        $('cf-dns').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('dns_list').then(function (d) { st.records = d.result.records; renderDns(); }).catch(fail($('cf-dns')));
    }
    $('cf-dns-filter').oninput = renderDns;
    function field(id, label, value, extra) {
        return '<label>' + esc(label) + ' <input type="text" id="' + id + '" value="' + esc(value === undefined || value === null ? '' : value) + '"' + (extra || '') + '></label>';
    }
    function dnsForm(r) {
        r = r || {type: 'A', name: '@', ttl: 1, proxied: true};
        var d = r.data || {};
        var box = $('cf-dns-form');
        box.style.display = 'block';
        box.innerHTML = '<h3>' + (r.id ? 'Edit record' : 'Add record') + '</h3><div class="ua-row"><label>Type <select id="cf-r-type">' +
            ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'].map(function (t) { return '<option' + (t === r.type ? ' selected' : '') + '>' + t + '</option>'; }).join('') + '</select></label>' +
            field('cf-r-name', 'Name', r.name) + field('cf-r-ttl', 'TTL (1 = auto)', r.ttl, ' style="min-width:80px"') + '</div>' +
            '<div class="ua-row" id="cf-r-main">' + field('cf-r-content', 'Content', r.content) + field('cf-r-priority', 'Priority', r.priority !== undefined && r.priority !== null ? r.priority : d.priority, ' style="min-width:80px"') + '</div>' +
            '<div class="ua-row" id="cf-r-srv">' + field('cf-r-weight', 'Weight', d.weight, ' style="min-width:80px"') + field('cf-r-port', 'Port', d.port, ' style="min-width:80px"') + field('cf-r-target', 'Target', d.target) + '</div>' +
            '<div class="ua-row" id="cf-r-caa">' + field('cf-r-flags', 'Flags', d.flags === undefined ? 0 : d.flags, ' style="min-width:60px"') + '<label>Tag <select id="cf-r-tag">' +
            ['issue', 'issuewild', 'iodef'].map(function (t) { return '<option' + (t === d.tag ? ' selected' : '') + '>' + t + '</option>'; }).join('') + '</select></label>' + field('cf-r-value', 'Value', d.value) + '</div>' +
            '<div class="ua-row"><label><input type="checkbox" id="cf-r-proxied"' + (r.proxied ? ' checked' : '') + '> Proxied (A, AAAA, CNAME)</label>' + field('cf-r-comment', 'Comment', r.comment) + '</div>' +
            '<div class="ua-row"><button type="button" class="ua-btn" id="cf-r-save">Save</button><button type="button" class="ua-btn ua-btn-secondary" id="cf-r-cancel">Cancel</button></div>';
        function shape() {
            var t = $('cf-r-type').value;
            $('cf-r-srv').style.display = t === 'SRV' ? 'flex' : 'none';
            $('cf-r-caa').style.display = t === 'CAA' ? 'flex' : 'none';
            $('cf-r-content').parentNode.style.display = (t === 'SRV' || t === 'CAA') ? 'none' : '';
            $('cf-r-priority').parentNode.style.display = (t === 'MX' || t === 'SRV') ? '' : 'none';
        }
        $('cf-r-type').onchange = shape; shape();
        $('cf-r-cancel').onclick = function () { box.style.display = 'none'; };
        $('cf-r-save').onclick = function () {
            var rec = {type: $('cf-r-type').value, name: $('cf-r-name').value, ttl: $('cf-r-ttl').value, content: $('cf-r-content').value,
                priority: $('cf-r-priority').value, weight: $('cf-r-weight').value, port: $('cf-r-port').value, target: $('cf-r-target').value,
                flags: $('cf-r-flags').value, tag: $('cf-r-tag').value, value: $('cf-r-value').value,
                proxied: $('cf-r-proxied').checked, comment: $('cf-r-comment').value};
            api('dns_save', {record_id: r.id || '', input: {record: rec}}).then(function () {
                box.style.display = 'none'; note($('cf-out'), 'Record saved.'); loadDns();
            }).catch(fail());
        };
    }
    $('cf-dns-new').onclick = function () { dnsForm(); };
    $('cf-dns').onclick = function (e) {
        var t = e.target;
        if (t.dataset.edit) { dnsForm(st.records.filter(function (r) { return r.id === t.dataset.edit; })[0]); }
        if (t.dataset.del && confirm('Delete this DNS record at Cloudflare?')) {
            api('dns_delete', {record_id: t.dataset.del}).then(function () { note($('cf-out'), 'Record deleted.'); loadDns(); }).catch(fail());
        }
    };
    $('cf-dns').onchange = function (e) {
        var t = e.target;
        if (!t.dataset.proxy) { return; }
        api('dns_proxied', {record_id: t.dataset.proxy, proxied: t.checked}).then(function () { note($('cf-out'), 'Proxy ' + (t.checked ? 'on' : 'off') + '.'); })
            .catch(function (err) { t.checked = !t.checked; fail()(err); });
    };
    $('cf-point').onclick = function () {
        api('point_here', {input: {name: $('cf-point-name').value}, proxied: $('cf-point-proxied').checked}).then(function (d) {
            note($('cf-out'), d.result.name + ' now points to ' + d.result.ip + (d.result.updated ? ' (record updated).' : ' (record added).')); loadDns();
        }).catch(fail());
    };
    $('cf-import').onclick = function () {
        var out = $('cf-import-out');
        out.innerHTML = '<p class="ua-muted">Reading this server\'s DNS…</p>';
        api('dns_import_preview').then(function (d) {
            var rows = d.result.rows, creatable = rows.filter(function (r) { return r.action === 'create'; });
            out.innerHTML = '<h3>Import preview from ' + esc(d.result.site) + '</h3><table class="ua-table"><thead><tr><th></th><th>Type</th><th>Name</th><th>Content</th><th>Result</th></tr></thead><tbody>' +
                rows.map(function (r) {
                    return '<tr><td>' + (r.action === 'create' ? '<input type="checkbox" data-key="' + esc(r.key) + '" checked>' : '') + '</td><td>' + esc(r.type) + '</td><td>' + esc(r.name) +
                        '</td><td style="word-break:break-all">' + esc(r.content || '') + '</td><td><span class="ua-badge ua-badge-' + ({create: 'info', exists: 'pass', conflict: 'warn', skip: 'warn'}[r.action]) + '">' +
                        esc(r.action) + '</span> ' + esc(r.reason || '') + '</td></tr>';
                }).join('') + '</tbody></table>' + (creatable.length ? '<div class="ua-row" style="margin-top:8px"><button type="button" class="ua-btn" id="cf-import-go">Import selected (' + creatable.length + ')</button></div>' : '<p class="ua-muted">Nothing new to import.</p>');
            if ($('cf-import-go')) {
                $('cf-import-go').onclick = function () {
                    var keys = Array.prototype.map.call(out.querySelectorAll('[data-key]:checked'), function (c) { return c.dataset.key; });
                    api('dns_import_apply', {input: {keys: keys}}).then(function (r) {
                        out.innerHTML = '<p>Imported ' + esc(r.result.created) + ' record(s).</p>' + (r.result.failed.length ? '<div class="ua-alert">' + r.result.failed.map(esc).join('<br>') + '</div>' : '');
                        loadDns();
                    }).catch(fail(out));
                };
            }
        }).catch(fail(out));
    };

    // ---------------------------------------------------------------- settings
    var LABELS = {development_mode: 'Development mode', cache_level: 'Cache level', browser_cache_ttl: 'Browser cache TTL (seconds, 0 = respect origin)',
        always_online: 'Always Online', ssl: 'SSL/TLS encryption mode', always_use_https: 'Always Use HTTPS', min_tls_version: 'Minimum TLS version',
        automatic_https_rewrites: 'Automatic HTTPS Rewrites', security_level: 'Security level', browser_check: 'Browser Integrity Check',
        brotli: 'Brotli', rocket_loader: 'Rocket Loader', early_hints: 'Early Hints', http3: 'HTTP/3 (with QUIC)'};
    function renderSettings() {
        var s = st.settings;
        Array.prototype.forEach.call(root.querySelectorAll('[data-settings]'), function (box) {
            var keys = s.groups[box.dataset.settings] || [];
            box.innerHTML = '<table class="ua-table" style="margin-top:12px">' + keys.map(function (k) {
                var cur = s.values[k];
                if (!cur) { return '<tr><th>' + esc(LABELS[k] || k) + '</th><td class="ua-muted">not available on this zone or plan</td></tr>'; }
                return '<tr><th>' + esc(LABELS[k] || k) + '</th><td><select data-setting="' + k + '"' + (cur.editable === false ? ' disabled' : '') + '>' +
                    s.choices[k].map(function (v) { return '<option' + (String(v) === String(cur.value) ? ' selected' : '') + '>' + esc(v) + '</option>'; }).join('') + '</select></td></tr>';
            }).join('') + '</table>';
        });
        var level = (s.values.security_level || {}).value;
        if (level && level !== 'under_attack') { st.securityLevel = level; }
        $('cf-uam-state').textContent = level === 'under_attack' ? 'on' : 'off';
    }
    function loadSettings() {
        if (st.settings) { renderSettings(); return Promise.resolve(); }
        return api('settings').then(function (d) { st.settings = d.result; renderSettings(); }).catch(fail());
    }
    root.addEventListener('change', function (e) {
        var key = e.target.dataset && e.target.dataset.setting;
        if (!key) { return; }
        var value = e.target.value;
        if (key === 'ssl' && value === 'flexible' && !confirm('Flexible breaks sites that redirect to HTTPS on this server (redirect loop). Continue?')) { renderSettings(); return; }
        api('setting_set', {setting: key, value: key === 'browser_cache_ttl' ? Number(value) : value}).then(function () {
            st.settings.values[key].value = key === 'browser_cache_ttl' ? Number(value) : value;
            renderSettings();
            note($('cf-out'), (LABELS[key] || key) + ' set to ' + value + '.');
        }).catch(function (err) { renderSettings(); fail()(err); });
    });
    $('cf-purge-all').onclick = function () {
        if (!confirm('Purge everything cached for ' + st.zoneName + '?')) { return; }
        api('purge', {everything: true}).then(function () { note($('cf-out'), 'Purge requested.'); }).catch(fail());
    };
    $('cf-purge-urls-go').onclick = function () {
        var urls = $('cf-purge-urls').value.split('\n').map(function (u) { return u.trim(); }).filter(Boolean);
        api('purge', {input: {urls: urls}}).then(function () { note($('cf-out'), 'Purged ' + urls.length + ' URL(s).'); }).catch(fail());
    };

    // ---------------------------------------------------------------- security
    function loadRules() {
        api('rules').then(function (d) {
            var rules = d.result.rules;
            $('cf-rules').innerHTML = rules.length ? '<table class="ua-table"><thead><tr><th>Mode</th><th>Target</th><th>Value</th><th>Note</th><th></th></tr></thead><tbody>' +
                rules.map(function (r) {
                    return '<tr><td>' + esc(r.mode) + '</td><td>' + esc(r.target) + '</td><td>' + esc(r.value) + '</td><td>' + esc(r.notes) + '</td><td>' +
                        (r.scope === 'zone' ? '<button type="button" class="ua-btn ua-btn-secondary" data-rule="' + esc(r.id) + '">Delete</button>' : '<span class="ua-muted">' + esc(r.scope) + ' rule</span>') + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No IP access rules.</p>';
        }).catch(fail($('cf-rules')));
    }
    function loadSecurity() { loadSettings(); loadRules(); }
    $('cf-uam').onclick = function () {
        var on = $('cf-uam-state').textContent !== 'on';
        api('under_attack', {enable: on, restore: st.securityLevel}).then(function (d) {
            if (st.settings && st.settings.values.security_level) { st.settings.values.security_level.value = d.result.value; renderSettings(); }
            note($('cf-out'), 'Under Attack mode ' + (on ? 'on.' : 'off (security level ' + d.result.value + ').'));
        }).catch(fail());
    };
    $('cf-rule-add').onclick = function () {
        api('rule_add', {input: {rule: {mode: $('cf-rule-mode').value, value: $('cf-rule-value').value, notes: $('cf-rule-notes').value}}}).then(function () {
            $('cf-rule-value').value = ''; note($('cf-out'), 'Rule added.'); loadRules();
        }).catch(fail());
    };
    $('cf-rules').onclick = function (e) {
        if (e.target.dataset.rule && confirm('Delete this access rule?')) {
            api('rule_delete', {rule_id: e.target.dataset.rule}).then(function () { loadRules(); }).catch(fail());
        }
    };

    // --------------------------------------------------------------- analytics
    function chart(series, keys, colors, fmt) {
        var w = 720, h = 180, pad = 30, n = series.length;
        if (!n) { return '<p class="ua-muted">No data for this period.</p>'; }
        var max = 1;
        series.forEach(function (p) { keys.forEach(function (k) { max = Math.max(max, p[k]); }); });
        var bw = (w - pad) / n;
        var bars = series.map(function (p, i) {
            return keys.map(function (k, j) {
                var bh = (p[k] / max) * (h - 20), x = pad + i * bw + j * (bw / keys.length);
                return '<rect x="' + x.toFixed(1) + '" y="' + (h - bh).toFixed(1) + '" width="' + Math.max(1, bw / keys.length - 1).toFixed(1) + '" height="' + bh.toFixed(1) +
                    '" fill="' + colors[j] + '"><title>' + esc(p.when) + ' ' + esc(k) + ': ' + esc(fmt(p[k])) + '</title></rect>';
            }).join('');
        }).join('');
        return '<svg viewBox="0 0 ' + w + ' ' + (h + 4) + '" style="width:100%;max-width:' + w + 'px;height:auto" role="img">' +
            '<text x="0" y="12" font-size="10" fill="currentColor">' + esc(fmt(max)) + '</text><line x1="' + pad + '" y1="' + h + '" x2="' + w + '" y2="' + h + '" stroke="#cbd5e1"/>' + bars + '</svg>' +
            '<div class="ua-muted">' + keys.map(function (k, j) { return '<span style="color:' + colors[j] + '">&#9632;</span> ' + esc(k); }).join(' &nbsp; ') + '</div>';
    }
    function loadAnalytics() {
        $('cf-analytics').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('analytics', {range: $('cf-range').value}).then(function (d) {
            var r = d.result, t = r.totals;
            var tiles = [['Requests', num(t.requests)], ['Unique visitors', num(t.uniques)], ['Page views', num(t.pageViews)], ['Bandwidth', human(t.bytes)],
                ['Cached requests', num(t.cachedRequests) + ' (' + (t.requests ? Math.round(100 * t.cachedRequests / t.requests) : 0) + '%)'],
                ['Uncached requests', num(t.uncachedRequests)], ['Cached bandwidth', human(t.cachedBytes)], ['Threats', num(t.threats)]];
            $('cf-analytics').innerHTML = '<div class="ua-grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));margin-bottom:12px">' +
                tiles.map(function (x) { return '<div class="ua-card" style="margin:0;padding:12px"><div class="ua-muted">' + esc(x[0]) + '</div><strong style="font-size:18px">' + esc(x[1]) + '</strong></div>'; }).join('') + '</div>' +
                '<h3>Requests (cached / uncached)</h3>' + chart(r.series.map(function (p) { return {when: p.when, cached: p.cachedRequests, uncached: p.requests - p.cachedRequests}; }), ['cached', 'uncached'], ['#16a34a', '#f59e0b'], num) +
                '<h3>Bandwidth</h3>' + chart(r.series.map(function (p) { return {when: p.when, bandwidth: p.bytes}; }), ['bandwidth'], ['#5b5fc7'], human) +
                '<h3>Threats</h3>' + chart(r.series.map(function (p) { return {when: p.when, threats: p.threats}; }), ['threats'], ['#dc2626'], num) +
                '<h3>Top countries</h3>' + (r.countries.length ? '<table class="ua-table"><thead><tr><th>Country</th><th>Requests</th><th>Threats</th></tr></thead><tbody>' +
                    r.countries.map(function (c) { return '<tr><td>' + esc(c.country) + '</td><td>' + num(c.requests) + '</td><td>' + num(c.threats) + '</td></tr>'; }).join('') + '</tbody></table>' : '<p class="ua-muted">No data.</p>');
        }).catch(fail($('cf-analytics')));
    }
    $('cf-analytics-load').onclick = loadAnalytics;

    // ------------------------------------------------------------ origin & log
    $('cf-origin').onclick = function () {
        if (!confirm('Create a Cloudflare Origin certificate and install it on the linked site? This replaces its current certificate.')) { return; }
        var b = this; UA.busy(b, true);
        api('origin_cert').then(function (d) {
            note($('cf-origin-out'), 'Installed on ' + d.result.site + ' for ' + d.result.hostnames.join(', ') + (d.result.expires_on ? ', valid until ' + d.result.expires_on : '') + '.');
        }).catch(fail($('cf-origin-out'))).then(function () { UA.busy(b, false); });
    };
    function loadAudit() {
        UA.api(base + 'audit_log', {}).then(function (d) {
            var e = d.result.entries.filter(function (x) { return !st.zone || !x.zone || x.zone === st.zone; });
            $('cf-audit').innerHTML = e.length ? '<table class="ua-table"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th><th>Token</th></tr></thead><tbody>' +
                e.map(function (x) {
                    return '<tr><td>' + esc(new Date(x.at * 1000).toLocaleString()) + '</td><td>' + esc(x.user) + '</td><td>' + esc(x.action) + '</td><td>' + esc(x.detail || '') + '</td><td>' + esc(x.token) + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No changes recorded yet.</p>';
        }).catch(fail($('cf-audit')));
    }

    loadState().then(loadZones);
})();
