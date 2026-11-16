/* DNS tools: DNSSEC and DNS templates. */
(function () {
    'use strict';
    var root = document.getElementById('ua-dnstools');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1', canTemplate = isAdmin || root.dataset.reseller === '1';
    var TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA'];
    var state = {fixed: [], previewed: false};

    function notify(e) { window.alert(e.message || e); }
    function scope() { return $('dt-scope') ? $('dt-scope').value : undefined; }
    function mode() { return root.querySelector('input[name="dt-mode"]:checked').value; }

    function recordTable(records, extra) {
        return '<table class="ua-table"><tr><th>Name</th><th>Type</th><th>Content</th><th>TTL</th><th>Prio</th>' + (extra ? '<th></th>' : '') + '</tr>' +
            records.map(function (r) {
                return '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.type) + '</td><td><code>' + esc(r.content) + '</code></td><td>' +
                    esc(r.ttl) + '</td><td>' + esc(r.prio) + '</td>' + (extra ? '<td class="ua-muted">' + esc(extra(r)) + '</td>' : '') + '</tr>';
            }).join('') + '</table>';
    }

    // ------------------------------------------------------------------ DNSSEC
    function showStatus(d) {
        var z = d.zone || {}, html = '';
        if (!d.ok) {
            html += '<div class="ua-alert">' + d.problems.map(esc).join('<br>') + '</div>';
        }
        if (d.facts && d.facts.webserver_open && isAdmin) {
            html += '<div class="ua-alert">The PowerDNS web server/API accepts connections from any address (webserver-allow-from). Restrict it to 127.0.0.1 in /etc/pdns/pdns.conf.</div>';
        }
        if (z.error) {
            html += '<div class="ua-alert">' + esc(z.error) + '</div>';
        } else if (z.secured) {
            html += '<p><span class="ua-badge ua-badge-pass">Signed</span> ' + esc(z.nsec || '') + ', ' + z.keys.length + ' key(s).</p>' +
                '<p><strong>Give this DS record to your registrar</strong> (SHA-256; some registrars ask for key tag, algorithm, digest type and digest separately):</p>' +
                (z.recommended_ds.length ? z.recommended_ds : z.ds).map(function (ds) {
                    return '<div class="ua-pre">' + esc(ds.record) + '\nKey tag: ' + esc(ds.tag) + '  Algorithm: ' + esc(ds.algorithm) +
                        '  Digest type: ' + esc(ds.digest_type) + '\nDigest: ' + esc(ds.digest) + '</div>';
                }).join('') +
                (z.dnskey.length ? '<details><summary>DNSKEY (for registrars that want the key instead)</summary>' + z.dnskey.map(function (k) {
                    return '<div class="ua-pre">' + esc(k.owner + ' IN DNSKEY ' + k.flags + ' ' + k.protocol + ' ' + k.algorithm + ' ' + k.key) + '</div>';
                }).join('') + '</details>' : '') +
                '<div class="ua-row" style="margin-top:12px"><button class="ua-btn ua-btn-secondary" id="dt-rectify">Rectify zone</button>' +
                '<span class="ua-muted">Run it after editing records of a signed zone.</span></div>' +
                '<div class="ua-row" style="margin-top:12px"><label><input type="checkbox" id="dt-ds-removed"> I removed the DS record at the registrar and waited for it to expire</label>' +
                '<button class="ua-btn ua-btn-secondary" id="dt-disable" style="color:#dc2626">Turn DNSSEC off</button></div>';
        } else {
            html += '<p><span class="ua-badge ua-badge-info">Not signed</span></p>' +
                (d.ok ? '<button class="ua-btn" id="dt-enable">Sign this zone (DNSSEC)</button>' : '');
        }
        $('dt-dnssec').innerHTML = html;
    }

    function check() {
        var zone = $('dt-zone').value;
        if (!zone) { return; }
        $('dt-dnssec').innerHTML = '<p class="ua-muted">Checking…</p>';
        api('dnssec_status', {zone: zone}).then(function (d) { showStatus(d.result); })
            .catch(function (e) { UA.showError($('dt-dnssec'), e); });
    }

    $('dt-status').onclick = check;
    $('dt-zone').addEventListener('change', check);
    $('dt-dnssec').addEventListener('click', function (event) {
        var t = event.target, zone = $('dt-zone').value;
        if (t.id === 'dt-enable') {
            if (!window.confirm('Sign ' + zone + '? After this, add the DS record shown at your registrar.')) { return; }
            UA.busy(t, true);
            api('dnssec_enable', {zone: zone}).then(check).catch(notify).then(function () { UA.busy(t, false); });
        } else if (t.id === 'dt-disable') {
            var confirmed = $('dt-ds-removed').checked;
            if (!confirmed) { notify('First remove the DS record at your registrar, wait for it to expire, then tick the box.'); return; }
            if (!window.confirm('Turn DNSSEC off for ' + zone + '?')) { return; }
            api('dnssec_disable', {zone: zone, confirmDsRemoved: true}).then(check).catch(notify);
        } else if (t.id === 'dt-rectify') {
            api('dnssec_rectify', {zone: zone}).then(function () { window.alert('Zone rectified.'); }).catch(notify);
        }
    });

    // ------------------------------------------------------------------ templates
    function row(r) {
        r = r || {name: '', type: 'A', content: '', ttl: 3600, prio: 0};
        var tr = document.createElement('tr');
        tr.innerHTML = '<td><input type="text" data-f="name" size="14"></td><td><select data-f="type">' +
            TYPES.map(function (t) { return '<option>' + t + '</option>'; }).join('') + '</select></td>' +
            '<td><input type="text" data-f="content" size="40"></td><td><input type="number" data-f="ttl" min="60" max="604800" style="width:90px"></td>' +
            '<td><input type="number" data-f="prio" min="0" max="65535" style="width:70px"></td><td><button class="ua-btn ua-btn-secondary" data-del="1">×</button></td>';
        tr.querySelector('[data-f="name"]').value = r.name;
        tr.querySelector('[data-f="type"]').value = r.type;
        tr.querySelector('[data-f="content"]').value = r.content;
        tr.querySelector('[data-f="ttl"]').value = r.ttl;
        tr.querySelector('[data-f="prio"]').value = r.prio;
        $('dt-records').appendChild(tr);
    }
    function setRows(records) {
        $('dt-records').innerHTML = '<tr><th>Name</th><th>Type</th><th>Content</th><th>TTL</th><th>Prio</th><th></th></tr>';
        (records || []).forEach(row);
    }
    function collect() {
        return {records: Array.prototype.map.call($('dt-records').querySelectorAll('tr'), function (tr) {
            var get = function (f) { var el = tr.querySelector('[data-f="' + f + '"]'); return el ? el.value : null; };
            if (get('type') === null) { return null; }
            return {name: get('name'), type: get('type'), content: get('content'), ttl: Number(get('ttl')), prio: Number(get('prio'))};
        }).filter(Boolean)};
    }
    function loadTemplate() {
        api('templates', {scope: scope()}).then(function (d) {
            var r = d.result;
            state.fixed = r.fixed.records;
            if (isAdmin && $('dt-scope').options.length === 1) {
                (r.resellers || []).forEach(function (x) {
                    var o = document.createElement('option');
                    o.value = 'reseller:' + x.id;
                    o.textContent = 'Reseller ' + x.name + (r.reseller_templates.indexOf(x.id) >= 0 ? ' (saved)' : '');
                    $('dt-scope').appendChild(o);
                });
                $('dt-ipv6').value = r.ipv6 || '';
            }
            $('dt-tpl-state').textContent = r.template ? 'A template is saved.' : 'No template saved: new zones get the fixed records (or the default template).';
            setRows(r.template ? r.template.records : []);
        }).catch(notify);
    }
    if (canTemplate) {
        $('dt-records').addEventListener('click', function (e) { if (e.target.dataset.del) { e.target.closest('tr').remove(); } });
        $('dt-add-row').onclick = function () { row(); };
        $('dt-load-fixed').onclick = function () { setRows(state.fixed); };
        if ($('dt-scope')) { $('dt-scope').addEventListener('change', loadTemplate); }
        $('dt-preview').onclick = function () {
            api('template_preview', {scope: scope(), template: collect(), zone: $('dt-zone').value || 'example.com'}).then(function (d) {
                $('dt-preview-out').innerHTML = '<p class="ua-muted">As it would be created for ' + esc(d.result.values.domain) + ':</p>' + recordTable(d.result.records);
            }).catch(function (e) { UA.showError($('dt-preview-out'), e); });
        };
        $('dt-save').onclick = function () {
            var body = {scope: scope(), template: collect()};
            if (isAdmin && scope() === 'default') { body.ipv6 = $('dt-ipv6').value.trim(); }
            api('template_save', body).then(function () { $('dt-tpl-state').textContent = 'Saved.'; }).catch(notify);
        };
        $('dt-remove').onclick = function () {
            if (!window.confirm('Remove this template? New zones then use the default template or the fixed records.')) { return; }
            api('template_save', {scope: scope(), template: null}).then(loadTemplate).catch(notify);
        };
        loadTemplate();
    }

    // ------------------------------------------------------------------ apply
    $('dt-apply-preview').onclick = function () {
        api('apply_preview', {zone: $('dt-apply-zone').value, mode: mode(), scope: scope()}).then(function (d) {
            var p = d.result;
            $('dt-apply-out').innerHTML = '<h3>To add (' + p.add.length + ')</h3>' + recordTable(p.add) +
                '<h3>To remove (' + p.remove.length + ')</h3>' + recordTable(p.remove) +
                (p.skipped.length ? '<h3>Skipped (' + p.skipped.length + ')</h3>' + recordTable(p.skipped, function (r) { return r.reason; }) : '');
            $('dt-apply').disabled = !(p.add.length || p.remove.length);
        }).catch(function (e) { UA.showError($('dt-apply-out'), e); $('dt-apply').disabled = true; });
    };
    $('dt-apply').onclick = function () {
        var body = {zone: $('dt-apply-zone').value, mode: mode(), scope: scope()};
        if (body.mode === 'replace') {
            if (!window.confirm('Apply the template and remove the records listed under "To remove"?')) { return; }
            body.confirm = true;
        }
        api('apply', body).then(function (d) {
            $('dt-apply-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Done</span> ' + d.result.added + ' added, ' + d.result.removed + ' removed.</p>';
            $('dt-apply').disabled = true;
        }).catch(notify);
    };
    root.querySelectorAll('input[name="dt-mode"]').forEach(function (el) { el.addEventListener('change', function () { $('dt-apply').disabled = true; }); });
    $('dt-apply-zone').addEventListener('change', function () { $('dt-apply').disabled = true; });

    api('zones', {}).then(function (d) {
        var options = d.result.zones.map(function (z) { return '<option>' + esc(z) + '</option>'; }).join('');
        $('dt-zone').innerHTML = options;
        $('dt-apply-zone').innerHTML = options;
        if (!d.result.zones.length) { $('dt-dnssec').innerHTML = '<p class="ua-muted">You have no DNS zones on this server.</p>'; } else { check(); }
    }).catch(function (e) { UA.showError($('dt-dnssec'), e); });
})();
