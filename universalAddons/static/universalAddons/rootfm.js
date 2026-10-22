(function () {
    'use strict';
    var root = document.getElementById('ua-rootfm');
    if (!root) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var state = {path: root.dataset.start, entries: [], editing: null};

    function api(name, body) { return UA.api(base + name, body); }
    function msg(html) { $('fm-msg').innerHTML = html || ''; }
    function fail(e) { msg('<div class="ua-alert">' + esc(e.message || e) + '</div>'); }
    function join(dir, name) { return (dir === '/' ? '' : dir) + '/' + name; }
    function size(n) {
        var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
        return (i ? n.toFixed(1) : n) + ' ' + units[i];
    }

    /* One request per attempt; returns the raw JSON so the protected flag can be inspected. */
    function fetchRaw(name, body) {
        return fetch(base + name, {method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf()}, body: JSON.stringify(body)})
            .then(function (r) {
                return r.json().catch(function () { return {status: 0, error_message: 'HTTP ' + r.status}; });
            });
    }
    /* Run a write action; on a protected path, explain and retry with unlock only if confirmed. */
    function guarded(name, body) {
        return fetchRaw(name, body).then(function (data) {
            if (data.status === 1) { return data; }
            if (data.protected && window.confirm(data.error_message +
                    '\n\nThis is a system path. Changing it can break the server. Continue?')) {
                body.unlock = true;
                return fetchRaw(name, body).then(function (again) {
                    if (again.status !== 1) { throw new Error(again.error_message || 'Request failed.'); }
                    return again;
                });
            }
            throw new Error(data.error_message || 'Request failed.');
        });
    }
    function csrf() { var m = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/); return m ? decodeURIComponent(m[1]) : ''; }

    function selected() {
        return Array.prototype.slice.call(root.querySelectorAll('.fm-sel:checked')).map(function (box) {
            return state.entries[Number(box.dataset.i)];
        });
    }
    function needOne() {
        var s = selected();
        if (s.length !== 1) { throw new Error('Select exactly one item.'); }
        return s[0];
    }
    function needSome() {
        var s = selected();
        if (!s.length) { throw new Error('Select one or more items.'); }
        return s.map(function (e) { return e.path; });
    }

    function render(listing) {
        state.path = listing.path;
        state.entries = listing.entries;
        $('fm-path').value = listing.path;
        $('fm-all').checked = false;
        $('fm-status').textContent = listing.entries.length + ' items' + (listing.truncated ? ' (truncated at 5000)' : '');
        root.querySelector('#fm-table tbody').innerHTML = listing.entries.map(function (e, i) {
            var icon = e.type === 'dir' ? 'fa-folder' : (e.type === 'link' ? 'fa-link' : 'fa-file');
            return '<tr><td><input type="checkbox" class="fm-sel" data-i="' + i + '"></td>' +
                '<td><a href="#" class="fm-open" data-i="' + i + '"><i class="fas ' + icon + '"></i> ' + esc(e.name) + '</a>' +
                (e.target ? ' <span class="ua-muted">→ ' + esc(e.target) + '</span>' : '') + '</td>' +
                '<td>' + (e.type === 'dir' ? '' : esc(size(e.size))) + '</td><td><code>' + esc(e.perms) + '</code> ' + esc(e.mode) + '</td>' +
                '<td>' + esc(e.owner) + ':' + esc(e.group) + '</td><td>' + esc(new Date(e.mtime * 1000).toLocaleString()) + '</td></tr>';
        }).join('');
    }

    function load(path) {
        msg('');
        return api('listing', {path: path || state.path, showHidden: $('fm-hidden').checked}).then(function (d) {
            render(d.result);
        }).catch(fail);
    }

    function openEntry(entry) {
        if (entry.type === 'dir' || (entry.type === 'link' && !/\.[a-z0-9]+$/i.test(entry.name))) { return load(entry.path); }
        return api('read', {path: entry.path}).then(function (d) {
            var r = d.result;
            state.editing = r;
            $('fm-editor').style.display = 'block';
            $('fm-editor-path').textContent = r.path;
            $('fm-editor-text').value = r.content;
            $('fm-editor-note').textContent = r.writable === 'yes' ? '' :
                (r.writable === 'protected' ? 'Protected system file: saving asks for confirmation.' : 'Read-only.');
            $('fm-editor').scrollIntoView({behavior: 'smooth'});
        }).catch(fail);
    }

    root.addEventListener('click', function (event) {
        var link = event.target.closest('.fm-open');
        if (link) { event.preventDefault(); openEntry(state.entries[Number(link.dataset.i)]); }
    });
    $('fm-all').addEventListener('change', function () {
        var on = this.checked;
        root.querySelectorAll('.fm-sel').forEach(function (b) { b.checked = on; });
    });
    $('fm-go').addEventListener('click', function () { load($('fm-path').value.trim()); });
    $('fm-path').addEventListener('keydown', function (e) { if (e.key === 'Enter') { load(this.value.trim()); } });
    $('fm-refresh').addEventListener('click', function () { load(); });
    $('fm-hidden').addEventListener('change', function () { load(); });
    $('fm-up').addEventListener('click', function () {
        if (state.path !== '/') { load(state.path.replace(/\/[^/]+$/, '') || '/'); }
    });

    $('fm-save').addEventListener('click', function () {
        var editing = state.editing, button = this;
        UA.busy(button, true);
        guarded('write', {path: editing.path, fileContent: $('fm-editor-text').value, sha256: editing.sha256})
            .then(function (d) { editing.sha256 = d.result.sha256; $('fm-editor-note').textContent = 'Saved.'; load(); })
            .catch(fail).then(function () { UA.busy(button, false); });
    });
    $('fm-close').addEventListener('click', function () { $('fm-editor').style.display = 'none'; state.editing = null; });

    var actions = {
        newfile: function () {
            var name = window.prompt('New file name');
            return name && guarded('create', {directory: state.path, name: name, kind: 'file'});
        },
        newdir: function () {
            var name = window.prompt('New folder name');
            return name && guarded('create', {directory: state.path, name: name, kind: 'dir'});
        },
        rename: function () {
            var e = needOne(), name = window.prompt('Rename ' + e.name + ' to', e.name);
            return name && name !== e.name && guarded('rename', {path: e.path, name: name});
        },
        copy: function () {
            var paths = needSome(), to = window.prompt('Copy to directory', state.path);
            return to && guarded('copy', {paths: paths, destination: to});
        },
        move: function () {
            var paths = needSome(), to = window.prompt('Move to directory', state.path);
            return to && guarded('move', {paths: paths, destination: to});
        },
        chmod: function () {
            var paths = needSome(), mode = window.prompt('New mode (e.g. 0644 or 0755)', selected()[0].mode);
            if (!mode) { return; }
            var recursive = selected().some(function (e) { return e.type === 'dir'; }) && window.confirm('Apply recursively to folder contents?');
            return guarded('chmod', {paths: paths, mode: mode, recursive: recursive});
        },
        chown: function () {
            var paths = needSome(), first = selected()[0];
            var value = window.prompt('Owner[:group]', first.owner + ':' + first.group);
            if (!value) { return; }
            var parts = value.split(':');
            var recursive = selected().some(function (e) { return e.type === 'dir'; }) && window.confirm('Apply recursively to folder contents?');
            return guarded('chown', {paths: paths, owner: parts[0], group: parts[1] || '', recursive: recursive});
        },
        compress: function () {
            var paths = needSome(), name = window.prompt('Archive name', 'archive-' + Date.now());
            if (!name) { return; }
            var format = window.prompt('Format: zip, tar, tar.gz, tar.bz2 or tar.xz', 'tar.gz');
            return format && guarded('compress', {paths: paths, destination: state.path, name: name, format: format});
        },
        extract: function () {
            var e = needOne(), to = window.prompt('Extract into directory', state.path);
            return to && guarded('extract', {path: e.path, destination: to});
        },
        download: function () {
            var e = needOne();
            window.location.href = root.dataset.download + '?path=' + encodeURIComponent(e.path);
        },
        checksum: function () {
            var e = needOne();
            return api('checksum', {path: e.path}).then(function (d) {
                msg('<div class="ua-card"><code>' + esc(d.result.sha256) + '</code> ' + esc(d.result.path) + '</div>');
                return 'keep';
            });
        },
        du: function () {
            var e = needOne();
            msg('<p class="ua-muted">Measuring…</p>');
            return api('du', {path: e.path}).then(function (d) {
                var r = d.result;
                msg('<div class="ua-card">' + esc(r.path) + ': <strong>' + esc(size(r.bytes)) + '</strong> in ' + esc(r.files) +
                    ' files' + (r.complete ? '' : ' (stopped after 20 s, partial)') + '</div>');
                return 'keep';
            });
        },
        trash: function () {
            var paths = needSome();
            return window.confirm('Move ' + paths.length + ' item(s) to the trash?\n\n' + paths.join('\n')) &&
                guarded('trash', {paths: paths});
        }
    };

    root.querySelectorAll('[data-act]').forEach(function (button) {
        button.addEventListener('click', function () {
            var result;
            try { result = actions[button.dataset.act](); } catch (e) { fail(e); return; }
            if (result && result.then) {
                UA.busy(button, true);
                result.then(function (r) { if (r !== 'keep') { load(); } })
                    .catch(fail).then(function () { UA.busy(button, false); });
            }
        });
    });

    $('fm-upload').addEventListener('change', function () {
        var files = Array.prototype.slice.call(this.files), input = this;
        var send = function (file, unlock) {
            var form = new FormData();
            form.append('file', file);
            form.append('directory', state.path);
            if (unlock) { form.append('unlock', '1'); }
            return fetch(root.dataset.upload, {method: 'POST', credentials: 'same-origin',
                headers: {'X-CSRFToken': csrf()}, body: form}).then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d.status === 1) { return d; }
                    if (d.protected && !unlock && window.confirm(d.error_message + '\n\nUpload into this system path anyway?')) {
                        return send(file, true);
                    }
                    throw new Error(file.name + ': ' + d.error_message);
                });
        };
        msg('<p class="ua-muted">Uploading ' + files.length + ' file(s)…</p>');
        files.reduce(function (chain, file) { return chain.then(function () { return send(file, false); }); }, Promise.resolve())
            .then(function () { msg(''); load(); }).catch(fail).then(function () { input.value = ''; });
    });

    $('fm-search-go').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('search', {path: state.path, pattern: $('fm-search').value}).then(function (d) {
            render({path: state.path, entries: d.result.results, truncated: !d.result.complete});
            $('fm-status').textContent = d.result.results.length + ' matches below ' + state.path + (d.result.complete ? '' : ' (partial)');
        }).catch(fail).then(function () { UA.busy(button, false); });
    });

    function loadTrash() {
        return api('list_trash', {}).then(function (d) {
            var items = d.result.items;
            $('fm-trash-list').innerHTML = items.length ? '<table class="ua-table"><tbody>' + items.map(function (t) {
                return '<tr><td>' + esc(t.path) + '</td><td>' + esc(new Date(t.deleted * 1000).toLocaleString()) + '</td>' +
                    '<td><button class="ua-btn ua-btn-secondary fm-restore" data-id="' + esc(t.id) + '">Restore</button> ' +
                    '<button class="ua-btn fm-purge" style="background:#dc2626" data-id="' + esc(t.id) + '">Delete forever</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p class="ua-muted">The trash is empty.</p>';
        }).catch(fail);
    }
    $('fm-trash-show').addEventListener('click', function () {
        var box = $('fm-trash');
        box.style.display = box.style.display === 'none' ? 'block' : 'none';
        if (box.style.display === 'block') { loadTrash(); }
    });
    $('fm-trash-list').addEventListener('click', function (event) {
        var restore = event.target.closest('.fm-restore'), purge = event.target.closest('.fm-purge');
        if (restore) { guarded('restore', {id: restore.dataset.id}).then(function () { loadTrash(); load(); }).catch(fail); }
        if (purge && window.confirm('Delete permanently? This cannot be undone.')) {
            api('purge', {ids: [purge.dataset.id]}).then(loadTrash).catch(fail);
        }
    });

    load(state.path);
})();
