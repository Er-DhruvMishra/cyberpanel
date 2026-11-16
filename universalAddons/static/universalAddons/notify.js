(function () {
    'use strict';
    var root = document.getElementById('ua-notify');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var admin = root.dataset.admin === '1';
    var data = null, editing = null;
    var LABEL = {email: 'E-mail', telegram: 'Telegram', slack: 'Slack', discord: 'Discord', webhook: 'Webhook'};

    function showFields() {
        var type = $('nt-type').value;
        Array.prototype.forEach.call(root.querySelectorAll('[data-for]'), function (el) {
            el.style.display = el.dataset['for'].split(' ').indexOf(type) >= 0 ? '' : 'none';
        });
    }

    function describe(c) {
        var p = c.public || {};
        if (c.type === 'email') { return esc(p.address); }
        if (c.type === 'telegram') { return 'chat ' + esc(p.chat_id) + (c.secret_set ? ' &middot; token saved' : ''); }
        if (c.type === 'webhook') { return esc(p.url) + (c.secret_set ? ' &middot; signing secret saved' : ''); }
        return c.secret_set ? 'webhook URL saved' : '';
    }

    function render() {
        var list = data.channels;
        $('nt-channels').innerHTML = list.length ? '<table class="ua-table"><thead><tr><th>Name</th><th>Type</th><th>Destination</th><th></th></tr></thead><tbody>' +
            list.map(function (c) {
                return '<tr><td><strong>' + esc(c.name) + '</strong>' + (c.enabled ? '' : ' <span class="ua-badge ua-badge-warn">off</span>') +
                    '</td><td>' + esc(LABEL[c.type] || c.type) + '</td><td>' + describe(c) + '</td><td style="white-space:nowrap">' +
                    '<button class="ua-btn ua-btn-secondary" data-test="' + esc(c.id) + '">Send test</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-edit="' + esc(c.id) + '">Edit</button> ' +
                    '<button class="ua-btn ua-btn-secondary" data-del="' + esc(c.id) + '">Delete</button></td></tr>';
            }).join('') + '</tbody></table>' :
            '<p class="ua-muted">No channels yet: alerts go by e-mail to the address on your IndiansCloud account.</p>';
        $('nt-events').innerHTML = data.events.map(function (e) {
            return '<label class="ua-check"><input type="checkbox" data-event="' + esc(e.key) + '"' + (e.enabled ? ' checked' : '') + '> <span>' + esc(e.label) + '</span></label>';
        }).join('');
        if (admin && data.thresholds) {
            $('nt-thresholds').style.display = '';
            $('nt-th-disk').value = data.thresholds.disk;
            $('nt-th-swap').value = data.thresholds.swap;
        }
        $('nt-log').innerHTML = data.log.length ? '<table class="ua-table"><thead><tr><th>When</th><th>Alert</th><th>Result</th></tr></thead><tbody>' +
            data.log.map(function (l) {
                return '<tr><td>' + esc(new Date(l.time * 1000).toLocaleString()) + '</td><td><span class="ua-badge ua-badge-' +
                    (l.severity === 'info' ? 'pass' : (l.severity === 'warning' ? 'warn' : 'fail')) + '">' + esc(l.severity) + '</span> ' +
                    esc(l.title) + '</td><td class="ua-muted">' + esc(l.result) + '</td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">Nothing sent yet.</p>';
    }

    function load() {
        api('overview', {}).then(function (d) { data = d.result; render(); })
            .catch(function (e) { UA.showError($('nt-channels'), e); });
    }

    function resetForm() {
        editing = null;
        ['nt-name', 'nt-address', 'nt-token', 'nt-chat', 'nt-hook', 'nt-url', 'nt-secret'].forEach(function (id) { $(id).value = ''; });
        $('nt-type').disabled = false;
        $('nt-enabled').checked = true;
        $('nt-cancel').style.display = 'none';
        $('nt-form-title').textContent = 'Add a channel';
        showFields();
    }

    function edit(id) {
        var c = data.channels.filter(function (x) { return x.id === id; })[0];
        if (!c) { return; }
        resetForm();
        editing = c.id;
        $('nt-type').value = c.type;
        $('nt-type').disabled = true;
        $('nt-name').value = c.name;
        $('nt-enabled').checked = c.enabled;
        $('nt-address').value = c.public.address || '';
        $('nt-chat').value = c.public.chat_id || '';
        $('nt-url').value = c.public.url || '';
        $('nt-cancel').style.display = '';
        $('nt-form-title').textContent = 'Edit ' + c.name;
        showFields();
    }

    $('nt-type').onchange = showFields;
    $('nt-cancel').onclick = resetForm;
    $('nt-save').onclick = function () {
        var type = $('nt-type').value, button = this;
        var channel = {type: type, name: $('nt-name').value, enabled: $('nt-enabled').checked};
        if (editing) { channel.id = editing; }
        if (type === 'email') { channel.address = $('nt-address').value; }
        if (type === 'telegram') { channel.token = $('nt-token').value; channel.chat_id = $('nt-chat').value; }
        if (type === 'slack' || type === 'discord') { channel.url = $('nt-hook').value; }
        if (type === 'webhook') { channel.url = $('nt-url').value; channel.signing_secret = $('nt-secret').value; }
        UA.busy(button, true);
        api('channel_save', {channel: channel}).then(function () {
            $('nt-form-note').textContent = 'Saved.';
            resetForm();
            load();
        }).catch(function (e) { $('nt-form-note').textContent = e.message; })
            .then(function () { UA.busy(button, false); });
    };
    $('nt-channels').onclick = function (event) {
        var t = event.target;
        if (t.dataset.edit) { edit(t.dataset.edit); }
        if (t.dataset.del && window.confirm('Delete this channel?')) {
            api('channel_delete', {id: t.dataset.del}).then(load).catch(function (e) { window.alert(e.message); });
        }
        if (t.dataset.test) {
            UA.busy(t, true);
            api('channel_test', {id: t.dataset.test}).then(function () { window.alert('Test message sent.'); load(); })
                .catch(function (e) { window.alert(e.message); }).then(function () { UA.busy(t, false); });
        }
    };
    $('nt-prefs').onclick = function () {
        var events = {}, body = {};
        Array.prototype.forEach.call(root.querySelectorAll('[data-event]'), function (el) { events[el.dataset.event] = el.checked; });
        body.events = events;
        if (admin) { body.thresholds = {disk: parseInt($('nt-th-disk').value, 10), swap: parseInt($('nt-th-swap').value, 10)}; }
        api('preferences', body).then(function (d) { data = d.result; render(); $('nt-prefs-note').textContent = 'Saved.'; })
            .catch(function (e) { $('nt-prefs-note').textContent = e.message; });
    };
    showFields();
    load();
})();
