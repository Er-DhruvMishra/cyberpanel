(function () {
    'use strict';
    var root = document.getElementById('ua-emaildebug');
    if (!root) { return; }
    var url = function (name) { return root.dataset['url' + name]; };
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc;

    root.querySelectorAll('.ua-tabs button').forEach(function (tab) {
        tab.addEventListener('click', function () {
            root.querySelectorAll('.ua-tabs button').forEach(function (b) { b.classList.remove('active'); });
            root.querySelectorAll('.ua-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            $('pane-' + tab.dataset.pane).classList.add('active');
        });
    });

    function table(results) {
        return '<table class="ua-table"><tbody>' + UA.resultRows(results) + '</tbody></table>';
    }

    function run(button, target, endpoint, body, render) {
        UA.busy(button, true);
        return UA.api(url(endpoint), body).then(function (data) {
            target.innerHTML = render(data.result);
            return data.result;
        }).catch(function (e) { UA.showError(target, e); })
          .then(function (r) { UA.busy(button, false); return r; });
    }

    UA.api(url('Context')).then(function (data) {
        var c = data.result;
        $('ua-ctx').textContent = ' Server IP ' + (c.server_ip || '?') + ', hostname ' + (c.hostname || '?') + '.';
    }).catch(function () {});

    $('dns-run').addEventListener('click', function () {
        var domain = $('dns-domain-other').value.trim() || $('dns-domain').value;
        run(this, $('dns-out'), 'Dns', {domain: domain}, function (r) {
            return '<h2>' + esc(r.domain) + '</h2>' + table(r.domain_checks) +
                '<h2 style="margin-top:18px">Sending IP ' + esc(r.server_ip) + '</h2>' + table(r.server_checks);
        });
    });

    $('ports-run').addEventListener('click', function () {
        run(this, $('ports-out'), 'Ports', {target: $('ports-target').value}, function (r) {
            return '<p class="ua-muted">Host ' + esc(r.host) + ', expected certificate name ' + esc(r.hostname || '-') + '</p>' + table(r.checks);
        });
    });

    function pairs(list, empty) {
        if (!list || !list.length) { return '<span class="ua-muted">' + empty + '</span>'; }
        return list.map(function (p) { return esc(p[0]) + ' <strong>' + esc(p[1]) + '</strong>'; }).join('<br>');
    }

    function messageRows(messages) {
        if (!messages.length) { return '<p class="ua-muted">No matching messages in the scanned log.</p>'; }
        return '<table class="ua-table"><thead><tr><th>Time</th><th>Queue ID</th><th>From / auth</th><th>Deliveries</th></tr></thead><tbody>' +
            messages.map(function (m) {
                var deliveries = m.deliveries.map(function (d) {
                    var cls = d.status === 'sent' ? 'pass' : (d.status === 'deferred' ? 'warn' : 'fail');
                    return '<div><span class="ua-badge ua-badge-' + cls + '">' + esc(d.status) + '</span> ' + esc(d.to) +
                        ' <span class="ua-muted">' + esc(d.dsn) + ' via ' + esc(d.relay) + '</span>' +
                        (d.reason ? '<div class="ua-fix">' + esc(d.reason) + '</div>' : '') + '</div>';
                }).join('') || '<span class="ua-muted">no delivery attempt logged</span>';
                return '<tr><td>' + esc(m.first_seen) + '</td><td>' + esc(m.qid) + '</td><td>' + esc(m.from) +
                    (m.sasl_username ? '<div class="ua-fix">auth: ' + esc(m.sasl_username) + '</div>' : '') +
                    (m.client ? '<div class="ua-fix">' + esc(m.client) + '</div>' : '') + '</td><td>' + deliveries + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function searchLogs(button, query) {
        return run(button, $('logs-out'), 'Logs', {query: query, statusFilter: $('logs-status').value}, function (r) {
            var s = r.summary;
            $('logs-summary').innerHTML = '<div class="ua-grid" style="margin-bottom:14px">' +
                '<div class="ua-card"><h2>Deliveries</h2>' + pairs(Object.keys(s.statuses).map(function (k) { return [k, s.statuses[k]]; }), 'none') + '</div>' +
                '<div class="ua-card"><h2>Top senders</h2>' + pairs(s.top_senders, 'none') + '</div>' +
                '<div class="ua-card"><h2>Deferral / bounce reasons</h2>' + pairs(s.top_problems, 'none') + '</div>' +
                '<div class="ua-card"><h2>Failed SMTP logins by IP</h2>' + pairs(s.sasl_failures, 'none') + '</div></div>';
            return '<p class="ua-muted">' + esc(r.total_matches) + ' matching of ' + esc(s.messages) + ' messages in the last ' +
                esc(r.lines_scanned) + ' lines of ' + esc(r.log) + ' (newest first, up to 200 shown).</p>' + messageRows(r.messages);
        });
    }
    $('logs-run').addEventListener('click', function () { searchLogs(this, $('logs-query').value.trim()); });

    $('queue-run').addEventListener('click', function () {
        run(this, $('queue-out'), 'Queue', {}, function (r) {
            if (r.error) { return '<div class="ua-alert">' + esc(r.error) + '</div>'; }
            return '<p><strong>' + esc(r.count) + '</strong> messages queued, oldest ' + esc(r.oldest_age_hours) + ' h.</p>' +
                '<div class="ua-grid"><div class="ua-card"><h2>By queue</h2>' +
                pairs(Object.keys(r.queues).map(function (k) { return [k, r.queues[k]]; }), 'empty') + '</div>' +
                '<div class="ua-card"><h2>Top destinations</h2>' + pairs(r.top_destinations, 'none') + '</div></div>';
        });
    });

    $('spam-run').addEventListener('click', function () {
        run(this, $('spam-out'), 'Spam', {emailMessage: $('spam-message').value}, function (r) {
            if (r.error) { return '<div class="ua-alert">' + esc(r.error) + '</div>'; }
            var score = r.score ? '<p><strong>' + esc(r.score.score) + '</strong> / ' + esc(r.score.threshold) + ' (' + esc(r.engine) + ')</p>' : '';
            return score + '<div class="ua-pre">' + esc(r.report) + '</div>';
        });
    });

    $('send-run').addEventListener('click', function () {
        var button = this;
        run(button, $('send-out'), 'Send', {sender: $('send-from').value.trim(), recipient: $('send-to').value.trim()}, function (r) {
            return '<p>Queued with Message-ID <code>' + esc(r.message_id) + '</code>. Tracing in the log…</p>';
        }).then(function (r) {
            if (!r || !r.message_id) { return; }
            $('logs-query').value = r.message_id;
            var attempts = 0;
            (function poll() {
                attempts += 1;
                UA.api(url('Logs'), {query: r.message_id}).then(function (data) {
                    var found = data.result.messages;
                    var done = found.length && found[0].deliveries.length;
                    $('send-out').innerHTML = '<p>Message-ID <code>' + esc(r.message_id) + '</code></p>' + messageRows(found);
                    if (!done && attempts < 10) { setTimeout(poll, 3000); }
                }).catch(function (e) { UA.showError($('send-out'), e); });
            })();
        });
    });
})();
