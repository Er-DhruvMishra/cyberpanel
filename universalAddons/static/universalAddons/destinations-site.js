/* "Back up to a backup destination" card on the Backup Website page. The destination list comes
   from the server, which offers only what the caller may use for the chosen site, labelled
   Mine / Site owner: x / Reseller: y. */
(function () {
    'use strict';
    var card = document.getElementById('site-destination-backup');
    if (!card) { return; }
    var base = card.dataset.base.replace(/\/$/, '') + '/ajax/';
    var site = document.getElementById('create-backup-select');
    var select = document.getElementById('site-destination-select');
    var button = document.getElementById('site-destination-backup-now');
    var status = document.getElementById('site-destination-status');

    function cookie(name) {
        var match = document.cookie.match('(?:^|; )' + name + '=([^;]*)');
        return match ? decodeURIComponent(match[1]) : '';
    }
    function post(name, body) {
        return fetch(base + name, {method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': cookie('csrftoken')},
            body: JSON.stringify(body)}).then(function (r) { return r.json(); }).then(function (d) {
                if (d.status !== 1) { throw new Error(d.error_message || 'Request failed.'); }
                return d;
            });
    }
    function add(value, label) {
        var option = document.createElement('option');
        option.value = value;
        option.textContent = label;
        select.appendChild(option);
    }
    function domain() { return (site && site.value || '').replace(/^string:/, ''); }

    function refresh() {
        select.innerHTML = '';
        button.disabled = true;
        status.textContent = '';
        if (!domain()) { add('', 'Choose a website first'); return; }
        post('site_destinations', {domain: domain()}).then(function (d) {
            if (!d.destinations.length) { add('', 'No destination available: add one on the Backup destinations page'); return; }
            d.destinations.forEach(function (x) { add(x.id, x.name + ' (' + x.provider_title + ') - ' + x.label); });
            button.disabled = false;
        }).catch(function (e) { add('', 'Unavailable'); status.textContent = e.message; });
    }

    function watch(jobId) {
        post('job', {job: jobId}).then(function (d) {
            var j = d.result;
            status.textContent = (j.step || 'Backup') + ': ' + j.state + (j.error ? ' - ' + j.error : '');
            if (j.state === 'running') { setTimeout(function () { watch(jobId); }, 5000); } else { button.disabled = false; }
        }).catch(function (e) { status.textContent = e.message; button.disabled = false; });
    }

    if (site) { site.addEventListener('change', refresh); }
    button.addEventListener('click', function () {
        if (!select.value) { return; }
        button.disabled = true;
        status.textContent = 'Starting…';
        post('backup_now', {domain: domain(), destination: select.value}).then(function (d) { watch(d.result.job_id); })
            .catch(function (e) { status.textContent = e.message; button.disabled = false; });
    });
    refresh();
}());
