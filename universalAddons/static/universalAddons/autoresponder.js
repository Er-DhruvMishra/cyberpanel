(function () {
    'use strict';
    var root = document.getElementById('ua-autoresponder');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';
    var state = {mailboxes: [], current: '', headers: null};

    function lines(text) {
        return text.split(/[\s,;]+/).map(function (v) { return v.trim(); }).filter(Boolean);
    }

    if (isAdmin) {
        var health = function () {
            $('ar-health-out').innerHTML = '<tbody><tr><td class="ua-muted">Checking…</td></tr></tbody>';
            api('health', {}).then(function (d) {
                $('ar-health-out').innerHTML = '<tbody>' + UA.resultRows(d.result.results) + '</tbody>';
                $('ar-dropin').textContent = d.result.dropin;
                $('ar-dropin-path').textContent = d.result.dropin_path;
                $('ar-dropin-box').style.display = d.result.problems.length ? '' : 'none';
                state.headers = d.result.headers;
                $('ar-score-note').textContent = 'Score header: ' + d.result.headers.score_header;
            }).catch(function (e) { UA.showError($('ar-health-out'), e); });
        };
        $('ar-health').addEventListener('click', health);
        health();
    }

    function renderMailboxes() {
        var filter = $('ar-filter').value.trim().toLowerCase();
        var rows = state.mailboxes.filter(function (m) { return !filter || m.email.toLowerCase().indexOf(filter) > -1; });
        $('ar-mailbox').innerHTML = '<option value="">Choose a mailbox…</option>' + rows.map(function (m) {
            return '<option value="' + esc(m.email) + '"' + (m.email === state.current ? ' selected' : '') + '>' +
                esc(m.email) + '</option>';
        }).join('');
    }

    function fill(result) {
        var v = result.settings.vacation, s = result.settings.spam;
        $('ar-enabled').checked = v.enabled;
        $('ar-start').value = v.start; $('ar-end').value = v.end; $('ar-days').value = v.days;
        $('ar-subject').value = v.subject; $('ar-body').value = v.body;
        $('ar-addresses').value = v.addresses.join('\n');
        $('ar-move').checked = s.move_spam; $('ar-folder').value = s.folder;
        $('ar-threshold').value = s.threshold === null ? '' : s.threshold;
        $('ar-threshold-action').value = s.threshold_action;
        $('ar-allow').value = s.allow.join('\n'); $('ar-block').value = s.block.join('\n');
        $('ar-block-action').value = s.block_action;
        $('ar-script').textContent = result.script || '(no rule is on)';
        $('ar-active').innerHTML = result.vacation_active ? '<span class="ua-badge ua-badge-pass">replying now</span>' :
            (v.enabled ? '<span class="ua-badge ua-badge-info">scheduled / ended</span>' : '');
    }

    function load(email) {
        state.current = email;
        $('ar-out').innerHTML = '';
        if (!email) { $('ar-forms').style.display = 'none'; return; }
        $('ar-status').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('get', {email: email}).then(function (d) {
            $('ar-status').innerHTML = '';
            fill(d.result);
            $('ar-forms').style.display = '';
        }).catch(function (e) { UA.showError($('ar-status'), e); $('ar-forms').style.display = 'none'; });
    }

    $('ar-filter').addEventListener('input', renderMailboxes);
    $('ar-mailbox').addEventListener('change', function () { load(this.value); });

    $('ar-save').addEventListener('click', function () {
        var button = this, threshold = $('ar-threshold').value.trim();
        var body = {
            email: state.current,
            vacation: {enabled: $('ar-enabled').checked, start: $('ar-start').value, end: $('ar-end').value,
                       days: Number($('ar-days').value), subject: $('ar-subject').value, body: $('ar-body').value,
                       addresses: lines($('ar-addresses').value)},
            spam: {move_spam: $('ar-move').checked, folder: $('ar-folder').value.trim() || 'Junk',
                   threshold: threshold === '' ? null : Number(threshold),
                   threshold_action: $('ar-threshold-action').value, allow: lines($('ar-allow').value),
                   block: lines($('ar-block').value), block_action: $('ar-block-action').value}
        };
        UA.busy(button, true);
        api('save', body).then(function (d) {
            fill(d.result);
            $('ar-out').innerHTML = '<p><span class="ua-badge ua-badge-pass">Saved</span> <span class="ua-muted">' +
                esc(d.result.note || (d.result.compiled ? 'Compiled and active.' : '')) + '</span></p>';
        }).catch(function (e) { UA.showError($('ar-out'), e); }).then(function () { UA.busy(button, false); });
    });

    api('mailboxes', {}).then(function (d) {
        state.mailboxes = d.result.mailboxes;
        var wanted = root.dataset.mailbox;
        renderMailboxes();
        if (wanted && state.mailboxes.some(function (m) { return m.email === wanted; })) {
            $('ar-mailbox').value = wanted;
            load(wanted);
        }
    }).catch(function (e) { UA.showError($('ar-status'), e); });
})();
