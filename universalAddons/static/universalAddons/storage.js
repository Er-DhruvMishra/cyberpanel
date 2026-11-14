(function () {
    'use strict';
    var root = document.getElementById('ua-storage');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var state = {categories: {}};
    var BADGE = {safe: 'pass', review: 'warn', report: 'info'};

    function human(kb) {
        var units = ['KB', 'MB', 'GB', 'TB'], i = 0;
        kb = Number(kb || 0);
        while (kb >= 1024 && i < units.length - 1) { kb /= 1024; i += 1; }
        return (i < 2 ? kb.toFixed(0) : kb.toFixed(1)) + ' ' + units[i];
    }
    function bar(fraction, colour) {
        return '<div style="background:var(--bg-secondary,#e5e7eb);border-radius:6px;height:10px;min-width:120px">' +
            '<div style="width:' + Math.min(100, Math.round(fraction * 100)) + '%;height:10px;border-radius:6px;background:' + (colour || '#5b5fc7') + '"></div></div>';
    }

    function watch(jobId, done) {
        $('st-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }, function (e, n) {
                var note = $('st-job-retry');
                if (!note) {
                    note = document.createElement('p');
                    note.id = 'st-job-retry';
                    note.className = 'ua-muted';
                    $('st-job-out').insertBefore(note, $('st-job-out').firstChild);
                }
                note.textContent = 'The panel is busy (' + e.message + '); reconnecting, attempt ' + n + '. The job keeps running on the server.';
            }).then(function (d) {
                var j = d.result;
                $('st-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' +
                    (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) + '">' + esc(j.state) + '</span></p>' +
                    (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-60).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 3000); } else if (done) { done(j); }
            }).catch(function (e) {
                UA.showError($('st-job-out'), e);
                var again = document.createElement('button');
                again.type = 'button';
                again.className = 'btn btn-default';
                again.textContent = 'Check again';
                again.onclick = function () { watch(jobId, done); };
                $('st-job-out').appendChild(again);
            });
        })();
    }

    function renderFilesystems(list) {
        $('st-fs').innerHTML = '<table class="ua-table"><tbody>' + list.map(function (f) {
            var used = f.used_mb / f.size_mb;
            return '<tr><td><strong>' + esc(f.mount) + '</strong> <span class="ua-muted">' + esc(f.device) + '</span></td><td style="width:40%">' +
                bar(used, used > 0.9 ? '#dc2626' : (used > 0.8 ? '#d97706' : '#16a34a')) + '</td><td>' + esc(human(f.used_mb * 1024)) + ' of ' +
                esc(human(f.size_mb * 1024)) + ' used, <strong>' + esc(human(f.free_mb * 1024)) + ' free</strong></td></tr>';
        }).join('') + '</tbody></table>';
    }

    function renderCategories(cats) {
        state.categories = cats;
        var order = Object.keys(cats).sort(function (a, b) { return cats[b].kb - cats[a].kb; });
        var safe = 0, review = 0;
        $('st-categories').innerHTML = '<thead><tr><th></th><th>What</th><th>Risk</th><th>Size</th><th>Details</th></tr></thead><tbody>' + order.map(function (id) {
            var c = cats[id], checkable = c.risk !== 'report' && c.kb > 0 && !c.error;
            if (c.risk === 'safe') { safe += c.kb; } else if (c.risk === 'review') { review += c.kb; }
            var items = (c.items || []).length ? '<details><summary class="ua-muted">' + c.items.length + ' item(s)</summary>' + c.items.map(function (it, n) {
                return '<div>' + (c.selectable && checkable ? '<label><input type="checkbox" class="st-item" data-cat="' + esc(id) + '" data-n="' + n + '"' +
                    (c.risk === 'safe' ? ' checked' : '') + '> ' : '') + '<code>' + esc(it.path) + '</code> ' + esc(human(it.kb)) +
                    (it.note ? ' <span class="ua-muted">' + esc(it.note) + '</span>' : '') + (c.selectable && checkable ? '</label>' : '') + '</div>';
            }).join('') + '</details>' : '';
            return '<tr><td>' + (checkable && !c.selectable ? '<input type="checkbox" class="st-cat" data-cat="' + esc(id) + '"' + (c.risk === 'safe' ? ' checked' : '') + '>' : '') +
                '</td><td><strong>' + esc(c.title) + '</strong>' + (c.count ? ' <span class="ua-muted">(' + esc(c.count) + ' files)</span>' : '') +
                (c.note ? '<div class="ua-fix">' + esc(c.note) + '</div>' : '') + (c.error ? '<div class="ua-fix">' + esc(c.error) + '</div>' : '') + items +
                '</td><td><span class="ua-badge ua-badge-' + BADGE[c.risk] + '">' + esc(c.risk) + '</span></td><td><strong>' + esc(human(c.kb)) + '</strong></td><td></td></tr>';
        }).join('') + '</tbody>';
        $('st-total').textContent = '(' + human(safe) + ' safe, ' + human(review) + ' to review)';
        $('st-results').style.display = 'block';
        updateSelected();
    }

    function selection() {
        var body = {}, total = 0;
        root.querySelectorAll('.st-cat:checked').forEach(function (box) {
            body['sel_' + box.dataset.cat] = true;
            total += state.categories[box.dataset.cat].kb;
        });
        root.querySelectorAll('.st-item:checked').forEach(function (box) {
            var c = state.categories[box.dataset.cat], item = c.items[Number(box.dataset.n)];
            (body['sel_' + box.dataset.cat] = body['sel_' + box.dataset.cat] || []).push(item.path);
            total += item.kb;
        });
        return {body: body, total: total};
    }
    function updateSelected() { $('st-selected').textContent = 'Selected: ' + human(selection().total); }
    root.addEventListener('change', function (e) { if (e.target.matches('.st-cat, .st-item')) { updateSelected(); } });

    function renderUsage(u) {
        renderFilesystems(u.filesystems);
        var biggest = u.directories.length ? u.directories[0].kb : 1;
        $('st-dirs').innerHTML = '<table class="ua-table"><tbody>' + u.directories.slice(0, 40).map(function (d) {
            return '<tr><td style="padding-left:' + (10 + d.level * 18) + 'px"><code>' + esc(d.path) + '</code></td><td style="width:35%">' + bar(d.kb / biggest) +
                '</td><td>' + esc(human(d.kb)) + '</td></tr>';
        }).join('') + '</tbody></table>';
        $('st-files').innerHTML = '<table class="ua-table"><tbody>' + u.large_files.map(function (f) {
            return '<tr><td><code>' + esc(f.path) + '</code>' + (f.explain ? '<div class="ua-fix">' + esc(f.explain) + '</div>' : '') +
                '</td><td>' + esc(human(f.kb)) + '</td><td class="ua-muted">' + esc(new Date(f.mtime * 1000).toLocaleDateString()) + '</td></tr>';
        }).join('') + '</tbody></table>';
        $('st-usage').style.display = 'block';
    }

    $('st-scan').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('scan', {}).then(function (d) {
            watch(d.result.job_id, function (j) {
                UA.busy(button, false);
                if (j.state !== 'done') { return; }
                renderUsage(j.result['Disk usage']);
                renderCategories(j.result['Reclaimable space']);
            });
        }).catch(function (e) { UA.busy(button, false); UA.showError($('st-job-out'), e); $('st-job').style.display = 'block'; });
    });

    function clean(dryRun) {
        var sel = selection();
        if (!Object.keys(sel.body).length) { UA.showError($('st-job-out'), new Error('Nothing selected.')); $('st-job').style.display = 'block'; return; }
        if (!dryRun && !window.confirm('Reclaim about ' + human(sel.total) + '? Files are deleted permanently (MySQL tables are backed up first).')) { return; }
        sel.body.dryRun = dryRun;
        api('clean', sel.body).then(function (d) {
            watch(d.result.job_id, function (j) {
                if (j.state === 'done') {
                    var r = j.result[Object.keys(j.result)[0]];
                    $('st-job-out').insertAdjacentHTML('afterbegin', '<p><span class="ua-badge ua-badge-pass">' + (dryRun ? 'Preview' : 'Done') + '</span> Free space: ' +
                        esc(human(r.free_before_mb * 1024)) + ' → ' + esc(human(r.free_after_mb * 1024)) + '. Log: <code>' + esc(r.log) + '</code></p>');
                }
            });
        }).catch(function (e) { UA.showError($('st-job-out'), e); $('st-job').style.display = 'block'; });
    }
    $('st-preview').addEventListener('click', function () { clean(true); });
    $('st-clean').addEventListener('click', function () { clean(false); });
})();
