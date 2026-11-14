(function () {
    'use strict';
    var root = document.getElementById('ua-emaillimits');
    if (!root || !document.getElementById('el-domains')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';
    var state = {domains: [], detail: null};

    function onOff(on) {
        return '<span class="ua-badge ua-badge-' + (on ? 'pass' : 'info') + '">' + (on ? 'on' : 'off') + '</span>';
    }
    function usage(used, limit) {
        var fraction = limit > 0 ? Math.min(1, used / limit) : (used > 0 ? 1 : 0);
        var colour = fraction >= 1 ? '#dc2626' : (fraction > 0.8 ? '#d97706' : '#16a34a');
        return '<div style="background:var(--bg-secondary,#e5e7eb);border-radius:6px;height:8px;min-width:100px;margin-bottom:4px">' +
            '<div style="width:' + Math.round(fraction * 100) + '%;height:8px;border-radius:6px;background:' + colour + '"></div></div>' +
            '<span class="ua-muted">' + esc(used) + ' / ' + esc(limit) + '</span>';
    }
    function int(input) {
        var value = input.value.trim();
        return /^\d{1,8}$/.test(value) ? Number(value) : NaN;
    }
    function syncNote(sync) {
        if (!sync) { return ''; }
        if (sync.error) { return '<div class="ua-alert">' + esc(sync.error) + '</div>'; }
        return '<p><span class="ua-badge ua-badge-pass">Saved</span> <span class="ua-muted">' +
            esc(sync.note || (sync.delivered ? 'cpecs updated (' + sync.delivered + ' change(s)).' : 'Nothing changed.')) + '</span></p>';
    }

    // ---- health (administrators)

    function loadHealth() {
        if (!isAdmin) { return; }
        $('el-health-out').innerHTML = '<tbody><tr><td class="ua-muted">Checking…</td></tr></tbody>';
        api('health', {}).then(function (d) {
            $('el-health-out').innerHTML = '<tbody>' + UA.resultRows(d.result.results) + '</tbody>';
            var cron = d.result.cron || {};
            $('el-repair').style.display = Object.keys(cron).some(function (k) { return !cron[k]; }) ? '' : 'none';
        }).catch(function (e) {
            $('el-health-out').innerHTML = '<tbody><tr><td><div class="ua-alert">' + esc(e.message) + '</div></td></tr></tbody>';
        });
    }
    if (isAdmin) {
        $('el-health').addEventListener('click', loadHealth);
        $('el-repair').addEventListener('click', function () {
            var button = this;
            UA.busy(button, true);
            api('repair_cron', {}).then(loadHealth).catch(function (e) {
                $('el-health-out').insertAdjacentHTML('beforeend', '<tbody><tr><td colspan="3"><div class="ua-alert">' + esc(e.message) + '</div></td></tr></tbody>');
            }).then(function () { UA.busy(button, false); });
        });
        $('el-policy').addEventListener('change', function () {
            var box = this;
            api('policy', {enabled: box.checked}).then(function () {
                $('el-policy-out').textContent = 'Saved.';
            }).catch(function (e) {
                box.checked = !box.checked;
                $('el-policy-out').textContent = e.message;
            });
        });
    }

    // ---- domains overview

    function renderDomains() {
        var filter = $('el-filter').value.trim().toLowerCase();
        var rows = state.domains.filter(function (d) { return !filter || d.domain.indexOf(filter) > -1; });
        if (!state.domains.length) {
            $('el-domains').innerHTML = '<p class="ua-muted">No email domains.</p>';
            return;
        }
        $('el-domains').innerHTML = '<table class="ua-table"><thead><tr><th>Domain</th><th>Limit</th><th>Mailboxes limited</th>' +
            '<th>This month</th><th></th></tr></thead><tbody>' + rows.map(function (d) {
                return '<tr><td><strong>' + esc(d.domain) + '</strong>' + (d.site !== d.domain ? '<div class="ua-fix">' + esc(d.site) + '</div>' : '') +
                    '</td><td>' + onOff(d.status) + '</td><td>' + esc(d.limited_mailboxes) + ' / ' + esc(d.mailboxes) + '</td><td>' +
                    usage(d.used, d.monthly) + '</td><td><button class="ua-btn ua-btn-secondary el-open" data-n="' +
                    state.domains.indexOf(d) + '">Manage</button></td></tr>';
            }).join('') + '</tbody></table>';
    }
    function loadDomains() {
        return UA.retry(function () { return api('overview', {}); }).then(function (d) {
            state.domains = d.result.domains;
            renderDomains();
        }).catch(function (e) { UA.showError($('el-domains'), e); });
    }
    $('el-filter').addEventListener('input', renderDomains);
    $('el-domains').addEventListener('click', function (event) {
        var button = event.target.closest('.el-open');
        if (button) { openDomain(state.domains[Number(button.dataset.n)].domain); }
    });
    $('el-refresh').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('refresh', {}).then(function (d) {
            var r = d.result.refresh || {};
            $('el-refresh-out').textContent = r.error || r.note || (r.flushed ? 'Live counters loaded from cpecs.' : '');
            state.domains = d.result.domains;
            renderDomains();
            if (state.detail) { openDomain(state.detail.domain); }
        }).catch(function (e) { $('el-refresh-out').textContent = e.message; })
            .then(function () { UA.busy(button, false); });
    });

    // ---- one domain

    function renderDetail(detail) {
        state.detail = detail;
        var limits = detail.limits;
        $('el-detail').style.display = 'block';
        $('el-detail-title').textContent = detail.domain;
        $('el-warnings').innerHTML = (detail.warnings || []).map(function (w) {
            return '<p class="ua-fix"><span class="ua-badge ua-badge-warn">Note</span> ' + esc(w) + '</p>';
        }).join('');
        $('el-domain-form').innerHTML = isAdmin ?
            '<div class="ua-row"><label><input type="checkbox" id="el-dom-enabled"' + (limits.status ? ' checked' : '') + '> Domain limit on</label>' +
            '<label>Monthly limit <input type="number" id="el-dom-monthly" min="0" value="' + esc(limits.monthly) + '" style="min-width:110px"></label>' +
            '<button class="ua-btn" id="el-dom-save">Save domain limit</button>' +
            '<span style="min-width:200px">' + usage(limits.used, limits.monthly) + '</span></div>' :
            '<div class="ua-row">Domain limit ' + onOff(limits.status) + ' <span style="min-width:200px">' + usage(limits.used, limits.monthly) + '</span></div>';
        if (isAdmin) { $('el-dom-save').addEventListener('click', saveDomain); }
        $('el-mailboxes').innerHTML = detail.mailboxes.length ? '<table class="ua-table"><thead><tr><th>Mailbox</th><th>Limit</th>' +
            '<th>Monthly</th><th>Hourly</th><th>This month</th><th>This hour</th><th></th></tr></thead><tbody>' +
            detail.mailboxes.map(function (m, n) {
                var enforced = m.status && limits.status;
                return '<tr><td><strong>' + esc(m.email) + '</strong>' + (m.status && !limits.status ? '<div class="ua-fix">not enforced: domain limit is off</div>' : '') +
                    '</td><td><label><input type="checkbox" class="el-mb-enabled" data-n="' + n + '"' + (m.status ? ' checked' : '') + '> on</label></td>' +
                    '<td><input type="number" class="el-mb-monthly" data-n="' + n + '" min="0" value="' + esc(m.monthly) + '" style="width:100px"></td>' +
                    '<td><input type="number" class="el-mb-hourly" data-n="' + n + '" min="0" value="' + esc(m.hourly) + '" style="width:80px"></td>' +
                    '<td>' + (enforced ? usage(m.used_month, m.monthly) : esc(m.used_month)) + '</td><td>' +
                    (enforced ? usage(m.used_hour, m.hourly) : esc(m.used_hour)) + '</td>' +
                    '<td><button class="ua-btn ua-btn-secondary el-mb-save" data-n="' + n + '">Save</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">This domain has no mailboxes.</p>';
    }
    function openDomain(domain) {
        $('el-out').innerHTML = '';
        return api('detail', {domain: domain}).then(function (d) {
            renderDetail(d.result);
            $('el-detail').scrollIntoView({behavior: 'smooth'});
        }).catch(function (e) { $('el-detail').style.display = 'block'; UA.showError($('el-out'), e); });
    }
    function after(button) {
        return function (d) {
            $('el-out').innerHTML = syncNote(d.result.sync) + (d.result.updated ? '<p class="ua-muted">' + esc(d.result.updated) + ' mailbox(es) updated.</p>' : '');
            renderDetail(d.result.detail);
            loadDomains();
        };
    }
    function fail(e) { UA.showError($('el-out'), e); }

    function saveDomain() {
        var button = this, monthly = int($('el-dom-monthly'));
        if (isNaN(monthly)) { return fail(new Error('Enter the monthly limit as a whole number.')); }
        UA.busy(button, true);
        api('save_domain', {domain: state.detail.domain, enabled: $('el-dom-enabled').checked, monthly: monthly})
            .then(after(button)).catch(fail).then(function () { UA.busy(button, false); });
    }
    $('el-mailboxes').addEventListener('click', function (event) {
        var button = event.target.closest('.el-mb-save');
        if (!button) { return; }
        var n = button.dataset.n, pick = function (cls) { return $('el-mailboxes').querySelector('.' + cls + '[data-n="' + n + '"]'); };
        var monthly = int(pick('el-mb-monthly')), hourly = int(pick('el-mb-hourly'));
        if (isNaN(monthly) || isNaN(hourly)) { return fail(new Error('Enter the limits as whole numbers.')); }
        UA.busy(button, true);
        api('save_mailbox', {domain: state.detail.domain, mailbox: state.detail.mailboxes[Number(n)].email,
                             enabled: pick('el-mb-enabled').checked, monthly: monthly, hourly: hourly})
            .then(after(button)).catch(fail).then(function () { UA.busy(button, false); });
    });
    $('el-bulk').addEventListener('click', function () {
        var button = this, monthly = int($('el-bulk-monthly')), hourly = int($('el-bulk-hourly'));
        if (isNaN(monthly) || isNaN(hourly)) { return fail(new Error('Enter the limits as whole numbers.')); }
        if (!window.confirm('Set these limits on all ' + state.detail.mailboxes.length + ' mailboxes of ' + state.detail.domain + '?')) { return; }
        UA.busy(button, true);
        api('apply_all', {domain: state.detail.domain, enabled: $('el-bulk-enabled').checked, monthly: monthly, hourly: hourly})
            .then(after(button)).catch(fail).then(function () { UA.busy(button, false); });
    });

    loadHealth();
    loadDomains();
})();
