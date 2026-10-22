/* Shared helpers for Universal Add-ons pages (no framework). */
(function (window) {
    'use strict';

    function cookie(name) {
        var match = document.cookie.match('(?:^|; )' + name.replace(/[.$?*|{}()[\]\\/+^]/g, '\\$&') + '=([^;]*)');
        return match ? decodeURIComponent(match[1]) : '';
    }

    function api(url, body) {
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': cookie('csrftoken')},
            body: JSON.stringify(body || {})
        }).then(function (response) {
            return response.json().catch(function () {
                return {status: 0, error_message: 'Unexpected response (HTTP ' + response.status + ').'};
            });
        }).then(function (data) {
            if (data.status !== 1) {
                throw new Error(data.error_message || data.errorMessage || 'Request failed.');
            }
            return data;
        });
    }

    function esc(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    var LABEL = {pass: 'OK', warn: 'Warning', fail: 'Problem', info: 'Info'};

    function resultRows(results) {
        return results.map(function (r) {
            return '<tr class="ua-' + esc(r.status) + '">' +
                '<td><span class="ua-badge ua-badge-' + esc(r.status) + '">' + esc(LABEL[r.status] || r.status) + '</span></td>' +
                '<td><strong>' + esc(r.title) + '</strong></td>' +
                '<td>' + esc(r.detail) + (r.fix ? '<div class="ua-fix">' + esc(r.fix) + '</div>' : '') + '</td></tr>';
        }).join('');
    }

    function busy(button, on) {
        if (!button) { return; }
        button.disabled = on;
        if (on) { button.dataset.label = button.textContent; button.textContent = 'Working…'; }
        else if (button.dataset.label) { button.textContent = button.dataset.label; }
    }

    function showError(target, error) {
        target.innerHTML = '<div class="ua-alert">' + esc(error.message || error) + '</div>';
    }

    window.UA = {api: api, esc: esc, resultRows: resultRows, busy: busy, showError: showError};
})(window);
