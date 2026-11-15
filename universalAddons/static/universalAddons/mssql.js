(function () {
    'use strict';
    var root = document.getElementById('ua-mssql');
    if (!root || !document.getElementById('sq-list')) { return; }
    var $ = function (id) { return document.getElementById(id); };
    var esc = UA.esc, base = root.dataset.base.replace(/\/$/, '') + '/ajax/';
    var api = function (name, body) { return UA.api(base + name, body); };
    var isAdmin = root.dataset.admin === '1';

    function secret(r) {
        return '<div class="ua-card"><p><span class="ua-badge ua-badge-pass">Done</span> Copy these now; the password is not shown again.</p>' +
            '<table class="ua-table"><tbody><tr><td>Database / login</td><td><code>' + esc(r.name) + '</code></td></tr>' +
            '<tr><td>Password</td><td><code>' + esc(r.password) + '</code></td></tr>' +
            '<tr><td>Connection string</td><td><code style="word-break:break-all">' + esc(r.connection_string) + '</code></td></tr></tbody></table></div>';
    }

    function loadList() {
        return api('databases', {}).then(function (d) {
            var dbs = d.result.databases;
            $('sq-list').innerHTML = dbs.length ? '<table class="ua-table"><thead><tr><th>Database</th><th>Site</th><th>Size</th><th>Created</th><th></th></tr></thead><tbody>' +
                dbs.map(function (db) {
                    return '<tr><td><strong>' + esc(db.name) + '</strong></td><td>' + esc(db.domain) + '</td><td>' + (db.size_mb === null || db.size_mb === undefined ? '' : esc(db.size_mb) + ' MB') +
                        '</td><td>' + esc(new Date(db.created * 1000).toLocaleDateString()) + '</td><td>' +
                        '<button class="ua-btn ua-btn-secondary sq-browse" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">Browse</button> ' +
                        '<button class="ua-btn ua-btn-secondary sq-reset" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">New password</button> ' +
                        '<button class="ua-btn sq-drop" style="background:#dc2626" data-name="' + esc(db.name) + '" data-domain="' + esc(db.domain) + '">Delete</button></td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No SQL Server databases yet.</p>';
        }).catch(function (e) { UA.showError($('sq-list'), e); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.sq-reset, .sq-drop');
        if (!t) { return; }
        if (t.classList.contains('sq-reset')) {
            if (!window.confirm('Generate a new password for ' + t.dataset.name + '? Apps using the old one stop connecting until updated.')) { return; }
            api('reset', {name: t.dataset.name, domain: t.dataset.domain}).then(function (d) { $('sq-created').innerHTML = secret(d.result); })
                .catch(function (e) { UA.showError($('sq-created'), e); });
        } else if (window.confirm('Delete database ' + t.dataset.name + ' and its login? This cannot be undone.')) {
            api('drop', {name: t.dataset.name, domain: t.dataset.domain}).then(loadList).catch(function (e) { UA.showError($('sq-list'), e); });
        }
    });

    // ------------------------------------------------------------------ viewer and row editing
    var viewing = null;  // {name, domain, schema, table, page, total, meta, result, sort, desc, filter...}
    var MAX_TEXT = 1000;

    function cookie(name) {
        var match = document.cookie.match('(?:^|; )' + name + '=([^;]*)');
        return match ? decodeURIComponent(match[1]) : '';
    }

    function storage(action, key, value) {
        // Remembered queries are a convenience; private windows or blocked storage just skip it.
        try {
            if (action === 'get') { return window.localStorage.getItem(key); }
            if (value) { window.localStorage.setItem(key, value); } else { window.localStorage.removeItem(key); }
        } catch (e) { /* ignore */ }
        return null;
    }

    function cell(value) {
        if (value === null || value === undefined) { return '<span class="ua-muted">NULL</span>'; }
        return esc(typeof value === 'object' ? JSON.stringify(value) : String(value));
    }

    function asText(value) {
        if (value === null || value === undefined) { return ''; }
        if (value === true) { return '1'; }
        if (value === false) { return '0'; }
        return typeof value === 'object' ? JSON.stringify(value) : String(value);
    }

    function truncated(value) {
        return typeof value === 'string' && value.length > MAX_TEXT && value.slice(-3) === '...';
    }

    var TD = '<td style="white-space:pre-wrap;max-width:420px;word-break:break-word">';

    function grid(columns, rows) {
        return '<table class="ua-table"><thead><tr>' + columns.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') +
            '</tr></thead><tbody>' + rows.map(function (r) {
                return '<tr>' + r.map(function (v) { return TD + cell(v) + '</td>'; }).join('') + '</tr>';
            }).join('') + '</tbody></table>';
    }

    function target(extra) {
        var body = {name: viewing.name, domain: viewing.domain};
        Object.keys(extra || {}).forEach(function (k) { body[k] = extra[k]; });
        return body;
    }

    function tableTarget(extra) {
        var body = target({schema: viewing.schema, table: viewing.table});
        Object.keys(extra || {}).forEach(function (k) { body[k] = extra[k]; });
        return body;
    }

    function queryKey() { return 'ua-mssql-query:' + viewing.domain + ':' + viewing.name; }

    function openViewer(name, domain) {
        viewing = {name: name, domain: domain};
        $('sq-viewer').style.display = 'block';
        $('sq-v-db').textContent = name;
        $('sq-v-table').style.display = 'none';
        ['sq-v-rows', 'sq-v-result', 'sq-v-structure', 'sq-v-insert', 'sq-v-msg'].forEach(function (id) { $(id).innerHTML = ''; });
        $('sq-v-sql').value = storage('get', queryKey()) || '';
        $('sq-v-write').checked = false;
        updateMode();
        $('sq-v-tables').innerHTML = '<p class="ua-muted">Loading…</p>';
        $('sq-viewer').scrollIntoView({behavior: 'smooth'});
        api('tables', target()).then(function (d) {
            var list = d.result.tables;
            $('sq-v-tables').innerHTML = list.length ? '<table class="ua-table"><thead><tr><th>Table</th><th>Rows</th><th>Size</th></tr></thead><tbody>' +
                list.map(function (t) {
                    return '<tr><td><a href="#" class="sq-v-table" data-schema="' + esc(t.schema) + '" data-table="' + esc(t.name) + '" data-rows="' + esc(t.rows === null ? '' : t.rows) + '">' +
                        esc(t.schema) + '.' + esc(t.name) + '</a>' + (t.kind === 'view' ? ' <span class="ua-badge ua-badge-info">view</span>' : '') + '</td><td>' +
                        (t.rows === null ? '' : esc(t.rows)) + '</td><td>' + (t.size_kb === null ? '' : esc(t.size_kb) + ' KB') + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No tables or views.</p>';
        }).catch(function (e) { UA.showError($('sq-v-tables'), e); });
    }

    function browseOptions() {
        var options = {pageSize: viewing.size, sort: viewing.sort || null, desc: !!viewing.desc};
        if (viewing.filterText) { options.filterColumn = viewing.filterColumn; options.filterText = viewing.filterText; }
        // In an object: CyberPanel's input filter screens top-level strings, and names/filters may contain [ ] ; ( ).
        return options;
    }

    function canEdit() { return viewing.meta && viewing.meta.editable && viewing.result && viewing.result.keys; }

    function metaOf(name) {
        return (viewing.meta ? viewing.meta.columns : []).filter(function (c) { return c.name === name; })[0];
    }

    function renderRows() {
        var r = viewing.result, edit = canEdit();
        if (!r.rows.length) { $('sq-v-rows').innerHTML = '<p class="ua-muted">No rows on this page.</p>'; return; }
        $('sq-v-rows').innerHTML = '<table class="ua-table"><thead><tr>' + r.columns.map(function (c) {
            var arrow = viewing.sort === c ? (viewing.desc ? ' &#9660;' : ' &#9650;') : '';
            return '<th><a href="#" class="sq-v-sort" data-col="' + esc(c) + '" title="Sort">' + esc(c) + arrow + '</a></th>';
        }).join('') + (edit ? '<th></th>' : '') + '</tr></thead><tbody>' + r.rows.map(function (row, i) {
            return '<tr data-i="' + i + '">' + row.map(function (v) { return TD + cell(v) + '</td>'; }).join('') +
                (edit ? '<td style="white-space:nowrap"><button class="ua-btn ua-btn-secondary sq-v-edit" data-i="' + i + '">Edit</button> ' +
                    '<button class="ua-btn sq-v-del" style="background:#dc2626" data-i="' + i + '">Delete</button></td>' : '') + '</tr>';
        }).join('') + '</tbody></table>';
    }

    function loadRows() {
        $('sq-v-rows').innerHTML = '<p class="ua-muted">Loading…</p>';
        return api('rows', tableTarget({page: viewing.page, browse: browseOptions()})).then(function (d) {
            var r = d.result, shown = r.rows.length, first = r.page * r.page_size;
            viewing.result = r;
            renderRows();
            $('sq-v-pager').style.display = 'flex';
            $('sq-v-page').textContent = shown ? 'Rows ' + (first + 1) + '–' + (first + shown) +
                (viewing.total && !viewing.filterText ? ' of about ' + viewing.total : '') + (viewing.filterText ? ' (filtered)' : '') : '';
            $('sq-v-prev').disabled = r.page === 0;
            $('sq-v-next').disabled = shown < r.page_size;
        }).catch(function (e) { UA.showError($('sq-v-rows'), e); });
    }

    function message(html) { $('sq-v-msg').innerHTML = html; }

    function done(r) {
        return '<p><span class="ua-badge ua-badge-pass">Saved</span> ' + esc(r.affected) + ' row(s) affected, committed.</p>';
    }

    function openTable(schema, table, total) {
        viewing.schema = schema; viewing.table = table; viewing.page = 0; viewing.total = total;
        viewing.sort = null; viewing.desc = false; viewing.filterText = ''; viewing.filterColumn = null;
        viewing.size = Number($('sq-v-size').value) || 50; viewing.meta = null; viewing.result = null;
        $('sq-v-table').style.display = 'block';
        $('sq-v-title').textContent = schema + '.' + table;
        $('sq-v-ftext').value = '';
        $('sq-v-insert').innerHTML = ''; message(''); $('sq-v-hint').textContent = '';
        $('sq-v-add').style.display = 'none';
        showTab('data');
        api('columns', tableTarget()).then(function (d) {
            viewing.meta = d.result;
            $('sq-v-fcol').innerHTML = d.result.columns.map(function (c) { return '<option value="' + esc(c.name) + '">' + esc(c.name) + '</option>'; }).join('');
            $('sq-v-add').style.display = d.result.kind === 'table' ? '' : 'none';
            $('sq-v-hint').textContent = d.result.editable ? 'Click a column name to sort. Edit and Delete change one row by its primary key.' :
                (d.result.kind === 'table' ? 'Click a column name to sort. This table has no primary key, so its rows cannot be edited or deleted here.' : 'Click a column name to sort. Views are read-only here.');
            if (viewing.result) { renderRows(); }
        }).catch(function (e) { UA.showError($('sq-v-msg'), e); });
        loadRows();
    }

    function showTab(tab) {
        $('sq-v-data').style.display = tab === 'data' ? 'block' : 'none';
        $('sq-v-structure').style.display = tab === 'structure' ? 'block' : 'none';
        Array.prototype.forEach.call(root.querySelectorAll('.sq-v-tab'), function (b) {
            b.classList.toggle('ua-btn-secondary', b.dataset.tab !== tab);
        });
        if (tab === 'structure') { loadStructure(); }
    }

    function yes(v) { return v ? 'yes' : ''; }

    function loadStructure() {
        $('sq-v-structure').innerHTML = '<p class="ua-muted">Loading…</p>';
        api('structure', tableTarget()).then(function (d) {
            var s = d.result, st = s.stats || {};
            var html = '<p class="ua-muted">' + esc(st.type || '') + ' · about ' + esc(st.rows === null || st.rows === undefined ? '?' : st.rows) + ' rows · ' +
                esc(st.reserved_kb === null || st.reserved_kb === undefined ? '?' : st.reserved_kb) + ' KB reserved (' + esc(st.data_kb || 0) + ' KB data) · modified ' + esc(st.modified || '') + '</p>';
            html += '<h4>Columns</h4><table class="ua-table"><thead><tr><th>Column</th><th>Type</th><th>Null</th><th>Default</th><th>Identity</th><th>Computed</th><th>Key</th></tr></thead><tbody>' +
                s.columns.map(function (c) {
                    return '<tr><td>' + esc(c.name) + '</td><td><code>' + esc(c.type) + '</code></td><td>' + yes(c.nullable) + '</td><td><code>' + esc(c['default'] || '') + '</code></td><td>' +
                        (c.identity ? esc('(' + c.seed + ', ' + c.increment + ')') : '') + '</td><td><code>' + esc(c.computed_definition || '') + '</code></td><td>' +
                        (c.pk ? '<span class="ua-badge ua-badge-pass">PK</span>' : '') + '</td></tr>';
                }).join('') + '</tbody></table>';
            html += '<h4>Indexes</h4>' + (s.indexes.length ? '<table class="ua-table"><thead><tr><th>Name</th><th>Type</th><th>Columns</th><th>Included</th><th>Unique</th><th>Size</th></tr></thead><tbody>' +
                s.indexes.map(function (i) {
                    return '<tr><td>' + esc(i.name) + (i.primary ? ' <span class="ua-badge ua-badge-pass">PK</span>' : '') + (i.disabled ? ' <span class="ua-badge ua-badge-fail">disabled</span>' : '') +
                        '</td><td>' + esc(i.type) + (i.filter ? '<br><code>WHERE ' + esc(i.filter) + '</code>' : '') + '</td><td>' + esc(i.columns || '') + '</td><td>' + esc(i.included || '') +
                        '</td><td>' + yes(i.unique) + '</td><td>' + (i.size_kb === null ? '' : esc(i.size_kb) + ' KB') + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No indexes.</p>');
            html += '<h4>Foreign keys</h4>' + (s.foreign_keys.length ? '<table class="ua-table"><thead><tr><th>Name</th><th>From</th><th>To</th><th>On delete / update</th></tr></thead><tbody>' +
                s.foreign_keys.map(function (f) {
                    return '<tr><td>' + esc(f.name) + (f.direction === 'in' ? ' <span class="ua-badge ua-badge-info">references this table</span>' : '') + '</td><td>' +
                        esc(f.schema + '.' + f.table + ' (' + (f.columns || '') + ')') + '</td><td>' + esc(f.ref_schema + '.' + f.ref_table + ' (' + (f.ref_columns || '') + ')') +
                        '</td><td>' + esc(f.on_delete + ' / ' + f.on_update) + '</td></tr>';
                }).join('') + '</tbody></table>' : '<p class="ua-muted">No foreign keys.</p>');
            $('sq-v-structure').innerHTML = html;
        }).catch(function (e) { UA.showError($('sq-v-structure'), e); });
    }

    // One input (plus a NULL box for nullable columns) for a column; `value` undefined = insert form.
    function field(c, value, i) {
        var id = 'sq-f-' + i, text = value === undefined ? '' : asText(value);
        var binary = ['binary', 'varbinary', 'image'].indexOf(c.base) >= 0;
        var locked = truncated(value) || (binary && typeof value === 'string' && value.slice(-3) === '...');
        var big = c.max_chars === null && ['text', 'ntext', 'xml', 'varchar', 'nvarchar', 'varbinary'].indexOf(c.base) >= 0;
        var placeholder = value === undefined ? (c['default'] ? 'default ' + c['default'] : (c.nullable ? 'NULL' : '')) : '';
        if (binary && !placeholder) { placeholder = '0x…'; }
        var input = big ? '<textarea id="' + id + '" rows="2" style="width:100%"' + (locked ? ' disabled' : '') + ' placeholder="' + esc(placeholder) + '">' + esc(text) + '</textarea>' :
            '<input id="' + id + '" value="' + esc(text) + '" style="width:100%"' + (locked ? ' disabled' : '') + ' placeholder="' + esc(placeholder) + '"' +
            (c.max_chars ? ' maxlength="' + esc(c.max_chars) + '"' : '') + '>';
        return input + (c.nullable && !locked ? '<label class="ua-muted" style="white-space:nowrap"><input type="checkbox" id="' + id + '-null"' +
            (value === null ? ' checked' : '') + '> NULL</label>' : '') + (locked ? '<div class="ua-muted">Too long to edit here.</div>' : '');
    }

    function readField(i) {
        var input = $('sq-f-' + i), isNull = $('sq-f-' + i + '-null');
        if (!input || input.disabled) { return undefined; }
        return isNull && isNull.checked ? null : input.value;
    }

    function rowKey(i) {
        var key = {};
        viewing.result.key_columns.forEach(function (name, k) { key[name] = viewing.result.keys[i][k]; });
        return key;
    }

    function editRow(i) {
        var tr = $('sq-v-rows').querySelector('tr[data-i="' + i + '"]'), row = viewing.result.rows[i];
        tr.innerHTML = viewing.result.columns.map(function (name, k) {
            var c = metaOf(name);
            return '<td>' + (c && c.editable ? field(c, row[k], k) : cell(row[k])) + '</td>';
        }).join('') + '<td style="white-space:nowrap"><button class="ua-btn sq-v-save" data-i="' + i + '">Save</button> ' +
            '<button class="ua-btn ua-btn-secondary sq-v-cancel">Cancel</button></td>';
    }

    function saveRow(i, button) {
        var row = viewing.result.rows[i], values = {};
        viewing.result.columns.forEach(function (name, k) {
            var c = metaOf(name), now = c && c.editable ? readField(k) : undefined;
            if (now === undefined) { return; }
            var before = row[k] === null ? null : asText(row[k]);
            if (now !== before) { values[name] = now; }  // only changed columns
        });
        if (!Object.keys(values).length) { renderRows(); return; }
        UA.busy(button, true);
        api('update_row', tableTarget({row: {key: rowKey(i), values: values}})).then(function (d) {
            message(done(d.result)); return loadRows();
        }).catch(function (e) { UA.showError($('sq-v-msg'), e); UA.busy(button, false); });
    }

    function deleteRow(i) {
        var key = rowKey(i);
        var label = Object.keys(key).map(function (k) { return k + ' = ' + key[k]; }).join(', ');
        if (!window.confirm('Delete the row where ' + label + '? This is committed immediately and cannot be undone.')) { return; }
        api('delete_row', tableTarget({row: {key: key}})).then(function (d) {
            message(done(d.result)); return loadRows();
        }).catch(function (e) { UA.showError($('sq-v-msg'), e); });
    }

    function insertForm() {
        var cols = viewing.meta.columns, skipped = cols.filter(function (c) { return !c.editable; });
        $('sq-v-insert').innerHTML = '<div class="ua-card"><h4>Insert a row into ' + esc(viewing.schema + '.' + viewing.table) + '</h4>' +
            '<p class="ua-muted">Empty fields use the column default. Tick NULL to store NULL.' +
            (skipped.length ? ' Filled in by SQL Server: ' + esc(skipped.map(function (c) { return c.name; }).join(', ')) + '.' : '') + '</p>' +
            '<table class="ua-table"><tbody>' + cols.map(function (c, k) {
                return c.editable ? '<tr><td><strong>' + esc(c.name) + '</strong><div class="ua-muted"><code>' + esc(c.type) + '</code>' + (c.nullable ? '' : ' required') +
                    '</div></td><td>' + field(c, undefined, 'n' + k) + '</td></tr>' : '';
            }).join('') + '</tbody></table><div class="ua-row"><button class="ua-btn" id="sq-v-insert-save">Insert</button>' +
            '<button class="ua-btn ua-btn-secondary" id="sq-v-insert-cancel">Cancel</button></div></div>';
    }

    function saveInsert(button) {
        var values = {};
        viewing.meta.columns.forEach(function (c, k) {
            if (!c.editable) { return; }
            var v = readField('n' + k);
            if (v === null || (v !== undefined && v !== '')) { values[c.name] = v; }  // empty = default
        });
        UA.busy(button, true);
        api('insert_row', tableTarget({row: {values: values}})).then(function (d) {
            $('sq-v-insert').innerHTML = ''; message(done(d.result)); return loadRows();
        }).catch(function (e) { UA.showError($('sq-v-msg'), e); UA.busy(button, false); });
    }

    function exportData(source, format, button) {
        var body = source === 'rows' ? tableTarget({page: viewing.page, browse: browseOptions()}) : target({content: $('sq-v-sql').value});
        body.source = source; body.format = format;
        var out = source === 'rows' ? $('sq-v-msg') : $('sq-v-result');
        UA.busy(button, true);
        fetch(base + 'export', {method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': cookie('csrftoken')}, body: JSON.stringify(body)})
            .then(function (response) {
                var type = response.headers.get('Content-Type') || '';
                var disposition = response.headers.get('Content-Disposition') || '';
                if (!response.ok || disposition.indexOf('attachment') < 0) {
                    return response.json().catch(function () { return {}; }).then(function (d) {
                        throw new Error(d.error_message || d.errorMessage || 'Export failed (HTTP ' + response.status + ').');
                    });
                }
                var match = disposition.match(/filename="([^"]+)"/);
                return response.blob().then(function (blob) {
                    var link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = match ? match[1] : 'export.' + format;
                    document.body.appendChild(link); link.click(); link.remove();
                    setTimeout(function () { URL.revokeObjectURL(link.href); }, 10000);
                    return type;
                });
            }).catch(function (e) { UA.showError(out, e); }).then(function () { UA.busy(button, false); });
    }

    function updateMode() {
        $('sq-v-mode').textContent = $('sq-v-write').checked ?
            'One SELECT, INSERT, UPDATE, DELETE or MERGE statement. Changes are committed. 30 seconds.' :
            'One SELECT or WITH statement, rolled back; at most 500 rows, 30 seconds, 2 MB.';
        $('sq-v-run').textContent = $('sq-v-write').checked ? 'Run and commit' : 'Run (read-only)';
    }

    function runQuery(button, confirmAll) {
        var sql = $('sq-v-sql').value, write = $('sq-v-write').checked, body = target({content: sql});
        // 'content': the key CyberPanel's input filter leaves unscreened, as SQL needs ; ' ( [ etc.
        if (write) { body.write = true; if (confirmAll) { body.confirm_all = true; } }
        storage('set', queryKey(), sql.length <= 20000 ? sql : '');
        UA.busy(button, true);
        $('sq-v-result').innerHTML = '';
        api('query', body).then(function (d) {
            var r = d.result;
            if (r.needs_confirm) {
                UA.busy(button, false);
                if (window.confirm(r.message + ' Run it anyway? This is committed and cannot be undone.')) { runQuery(button, true); }
                return;
            }
            if (r.verb) {
                $('sq-v-result').innerHTML = '<p><span class="ua-badge ua-badge-pass">Committed</span> ' + esc(String(r.verb).toUpperCase()) + ': ' + esc(r.affected) + ' row(s) affected.' +
                    (r.capped ? ' Showing the first 500 OUTPUT rows.' : '') + '</p>' + (r.columns.length ? grid(r.columns, r.rows) : '');
                if (viewing.result) { loadRows(); }
            } else {
                $('sq-v-result').innerHTML = '<p class="ua-muted">' + esc(r.rows.length) + ' row(s)' + (r.capped ? ' (limit of 500 reached)' : '') + ', read-only and rolled back.</p>' +
                    (r.columns.length ? grid(r.columns, r.rows) : '');
            }
            UA.busy(button, false);
        }).catch(function (e) { UA.showError($('sq-v-result'), e); UA.busy(button, false); });
    }

    root.addEventListener('click', function (event) {
        var t = event.target.closest('.sq-browse, .sq-v-table, .sq-v-sort, .sq-v-tab, .sq-v-edit, .sq-v-del, .sq-v-save, .sq-v-cancel, .sq-v-export');
        if (!t) { return; }
        event.preventDefault();
        if (t.classList.contains('sq-browse')) { openViewer(t.dataset.name, t.dataset.domain); }
        else if (t.classList.contains('sq-v-table')) { openTable(t.dataset.schema, t.dataset.table, t.dataset.rows); }
        else if (t.classList.contains('sq-v-sort')) {
            viewing.desc = viewing.sort === t.dataset.col ? !viewing.desc : false;
            viewing.sort = t.dataset.col; viewing.page = 0; loadRows();
        }
        else if (t.classList.contains('sq-v-tab')) { showTab(t.dataset.tab); }
        else if (t.classList.contains('sq-v-edit')) { renderRows(); editRow(Number(t.dataset.i)); }
        else if (t.classList.contains('sq-v-del')) { deleteRow(Number(t.dataset.i)); }
        else if (t.classList.contains('sq-v-save')) { saveRow(Number(t.dataset.i), t); }
        else if (t.classList.contains('sq-v-cancel')) { renderRows(); }
        else if (t.classList.contains('sq-v-export')) { exportData(t.dataset.source, t.dataset.format, t); }
    });
    $('sq-v-close').addEventListener('click', function () { $('sq-viewer').style.display = 'none'; viewing = null; });
    $('sq-v-prev').addEventListener('click', function () { if (viewing.page > 0) { viewing.page -= 1; loadRows(); } });
    $('sq-v-next').addEventListener('click', function () { viewing.page += 1; loadRows(); });
    $('sq-v-size').addEventListener('change', function () { viewing.size = Number(this.value); viewing.page = 0; loadRows(); });
    $('sq-v-filter').addEventListener('click', function () {
        viewing.filterColumn = $('sq-v-fcol').value; viewing.filterText = $('sq-v-ftext').value; viewing.page = 0; loadRows();
    });
    $('sq-v-ftext').addEventListener('keydown', function (event) { if (event.key === 'Enter') { $('sq-v-filter').click(); } });
    $('sq-v-unfilter').addEventListener('click', function () { $('sq-v-ftext').value = ''; viewing.filterText = ''; viewing.page = 0; loadRows(); });
    $('sq-v-add').addEventListener('click', function () { if (viewing.meta) { insertForm(); } });
    $('sq-v-insert').addEventListener('click', function (event) {
        if (event.target.id === 'sq-v-insert-save') { saveInsert(event.target); }
        if (event.target.id === 'sq-v-insert-cancel') { $('sq-v-insert').innerHTML = ''; }
    });
    $('sq-v-write').addEventListener('change', updateMode);
    $('sq-v-run').addEventListener('click', function () { runQuery(this, false); });

    $('sq-create').addEventListener('click', function () {
        var button = this;
        UA.busy(button, true);
        api('create', {domain: $('sq-domain').value, name: $('sq-name').value.trim().toLowerCase(), passwordByPass: $('sq-password').value})
            .then(function (d) { $('sq-password').value = ''; $('sq-created').innerHTML = secret(d.result); loadList(); })
            .catch(function (e) { UA.showError($('sq-created'), e); }).then(function () { UA.busy(button, false); });
    });

    function watch(jobId) {
        $('sq-job').style.display = 'block';
        (function poll() {
            UA.retry(function () { return api('job', {job: jobId}); }).then(function (d) {
                var j = d.result;
                $('sq-job-out').innerHTML = '<p>' + esc(j.step || '') + ' <span class="ua-badge ua-badge-' + (j.state === 'done' ? 'pass' : (j.state === 'running' ? 'info' : 'fail')) +
                    '">' + esc(j.state) + '</span></p>' + (j.error ? '<div class="ua-alert">' + esc(j.error) + '</div>' : '') + '<div class="ua-pre">' + esc((j.log || []).slice(-80).join('\n')) + '</div>';
                if (j.state === 'running') { setTimeout(poll, 5000); } else { loadServer(); loadList(); }
            }).catch(function (e) { UA.showError($('sq-job-out'), e); });
        })();
    }

    function loadServer() {
        return api('overview', {}).then(function (d) {
            var s = d.result;
            var checks = '<table class="ua-table"><tbody>' + s.preflight.filter(function (c) { return c.id !== 'installed'; }).map(function (c) {
                return '<tr><td><span class="ua-badge ua-badge-' + (c.ok ? 'pass' : 'fail') + '">' + (c.ok ? 'OK' : 'No') + '</span></td><td>' + esc(c.detail) + '</td></tr>';
            }).join('') + '</tbody></table>';
            if (s.installed) {
                $('sq-server').innerHTML = '<p>SQL Server ' + esc(s.product || '') + ' Express <span class="ua-badge ua-badge-' + (s.running ? 'pass' : 'fail') + '">' +
                    (s.running ? 'running' : 'stopped') + '</span> · memory cap ' + esc(s.memory_limit_mb || '?') + ' MB · 127.0.0.1:1433</p>' +
                    '<div class="ua-row"><button class="ua-btn ua-btn-secondary sq-svc" data-action="restart">Restart</button>' +
                    '<button class="ua-btn ua-btn-secondary sq-svc" data-action="' + (s.running ? 'stop' : 'start') + '">' + (s.running ? 'Stop' : 'Start') + '</button></div>';
                $('sq-install').style.display = 'none';
            } else {
                var ready = s.preflight.every(function (c) { return c.ok; });
                $('sq-server').innerHTML = '<p>Not installed. Requirements on this server:</p>' + checks +
                    (ready ? '' : '<div class="ua-alert">This server does not meet Microsoft\'s minimum requirements, so installation is disabled.</div>');
                $('sq-install').style.display = ready ? 'block' : 'none';
                $('sq-eula-link').href = s.eula_url;
                $('sq-memory').value = s.default_memory_limit_mb;
            }
        }).catch(function (e) { UA.showError($('sq-server'), e); });
    }

    if (isAdmin) {
        $('sq-install-btn').addEventListener('click', function () {
            if (!$('sq-eula').checked) { UA.showError($('sq-out'), new Error('Accept the licence terms first.')); return; }
            api('install', {acceptEula: true, memoryLimitMb: Number($('sq-memory').value)}).then(function (d) { watch(d.result.job_id); })
                .catch(function (e) { UA.showError($('sq-out'), e); });
        });
        root.addEventListener('click', function (event) {
            var t = event.target.closest('.sq-svc');
            if (t) { api('service', {action: t.dataset.action}).then(loadServer).catch(function (e) { UA.showError($('sq-out'), e); }); }
        });
        loadServer();
    }
    loadList();
})();
