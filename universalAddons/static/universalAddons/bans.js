/* Fail2ban ban manager (administrators). */
(function () {
    'use strict';
    var root = document.getElementById('ua-bans');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, q) { return UA.api(base + name, q ? {q: q} : {}); };
    var state = {data: null};

    function notify(e) { window.alert(e.message || e); }
    function n(value) { return value === null || value === undefined ? '–' : esc(value); }

    function renderJails() {
        var d = state.data, filter = $('bn-filter').value.trim();
        if (d.problem) { $('bn-jails').innerHTML = '<div class="ua-alert">' + esc(d.problem) + '</div>'; return; }
        $('bn-total').textContent = d.total_banned + ' address(es) banned now';
        $('bn-jail').innerHTML = d.jails.map(function (j) { return '<option>' + esc(j.name) + '</option>'; }).join('');
        $('bn-jails').innerHTML = d.jails.map(function (j) {
            var banned = j.banned.filter(function (ip) { return !filter || ip.indexOf(filter) >= 0; });
            return '<h3>' + esc(j.name) + ' <span class="ua-muted">filter ' + esc(j.filter || '?') + '</span></h3>' +
                '<p class="ua-muted">Banned now ' + n(j.currently_banned) + ', total ' + n(j.total_banned) + ' &middot; failed now ' +
                n(j.currently_failed) + ', total ' + n(j.total_failed) + ' &middot; logs ' + esc(j.logs.join(', ') || '–') +
                ' &middot; ignores ' + esc(j.ignoreip.join(' ') || '–') + '</p>' +
                (banned.length ? '<table class="ua-table">' + banned.map(function (ip) {
                    return '<tr><td><code>' + esc(ip) + '</code></td><td><button class="ua-btn ua-btn-secondary" data-unban="' + esc(ip) +
                        '" data-jail="' + esc(j.name) + '">Unban</button></td></tr>';
                }).join('') + '</table>' : '<p class="ua-muted">No banned addresses' + (filter ? ' match.' : '.') + '</p>');
        }).join('') || '<p class="ua-muted">No jails are running.</p>';
        $('bn-dropin').textContent = 'Kept in ' + d.dropin + ', added to what jail.local already ignores. Every change is tested, backed up and followed by fail2ban-client reload.';
        $('bn-whitelist').innerHTML = d.whitelist.length ? '<table class="ua-table">' + d.whitelist.map(function (e) {
            return '<tr><td><code>' + esc(e) + '</code></td><td><button class="ua-btn ua-btn-secondary" data-wlremove="' + esc(e) + '">Remove</button></td></tr>';
        }).join('') + '</table>' : '<p class="ua-muted">No panel-managed entries.</p>';
        var fw = d.firewall || {};
        $('bn-firewall').innerHTML = (fw.entries || []).length ? '<table class="ua-table"><tr><th>Address</th><th>Reason</th><th>Added</th><th>Active</th></tr>' +
            fw.entries.map(function (e) {
                return '<tr><td><code>' + esc(e.target) + '</code></td><td>' + esc(e.reason || '') + '</td><td>' +
                    esc(e.added ? new Date(e.added * 1000).toLocaleString() : '') + '</td><td>' + (e.active ? 'yes' : 'no') + '</td></tr>';
            }).join('') + '</table>' : '<p class="ua-muted">' + esc(fw.error || 'None.') + '</p>';
    }

    function load() {
        return api('overview').then(function (d) { state.data = d.result; renderJails(); })
            .catch(function (e) { UA.showError($('bn-jails'), e); });
    }

    $('bn-refresh').onclick = load;
    $('bn-filter').addEventListener('input', function () { if (state.data) { renderJails(); } });
    $('bn-search').onclick = function () {
        api('search', {ip: $('bn-ip').value.trim()}).then(function (d) {
            var r = d.result, list = function (a) { return a.length ? esc(a.join(', ')) : 'none'; };
            $('bn-search-out').innerHTML = '<table class="ua-table"><tr><td>Banned in</td><td>' + list(r.banned_in) + '</td></tr>' +
                '<tr><td>Ignored by</td><td>' + list(r.ignored_in) + '</td></tr><tr><td>Panel whitelist</td><td>' + list(r.whitelisted) +
                '</td></tr><tr><td>Firewall blocks</td><td>' + list(r.firewall) + '</td></tr></table>' +
                r.banned_in.map(function (j) {
                    return '<button class="ua-btn ua-btn-secondary" data-unban="' + esc(r.ip) + '" data-jail="' + esc(j) + '">Unban from ' + esc(j) + '</button> ';
                }).join('');
        }).catch(function (e) { UA.showError($('bn-search-out'), e); });
    };
    $('bn-ban').onclick = function () {
        var ip = $('bn-ip').value.trim(), jail = $('bn-jail').value;
        if (!window.confirm('Ban ' + ip + ' in ' + jail + '?')) { return; }
        api('ban', {jail: jail, ip: ip}).then(function (d) {
            if (d.result.warnings && d.result.warnings.length) { window.alert(d.result.warnings.join('\n')); }
            return load();
        }).catch(notify);
    };
    $('bn-wl-add').onclick = function () {
        var b = this;
        UA.busy(b, true);
        api('whitelist_add', {entry: $('bn-entry').value.trim()}).then(function () { $('bn-entry').value = ''; return load(); })
            .catch(notify).then(function () { UA.busy(b, false); });
    };
    root.addEventListener('click', function (event) {
        var t = event.target, ds = t.dataset || {};
        if (ds.unban) {
            api('unban', {jail: ds.jail, ip: ds.unban}).then(load).catch(notify);
        } else if (ds.wlremove) {
            if (window.confirm('Remove ' + ds.wlremove + ' from the whitelist and reload fail2ban?')) {
                api('whitelist_remove', {entry: ds.wlremove}).then(load).catch(notify);
            }
        }
    });
    load();
})();
