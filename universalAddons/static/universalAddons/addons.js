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
            return response;
        }, function (networkError) {
            var error = new Error('The panel could not be reached (' + networkError.message + ').');
            error.transient = true;
            throw error;
        }).then(function (response) {
            return response.json().catch(function () {
                // A 502/503/504 page from the web server, or a body cut short: the panel was busy
                // or restarting, not a refusal from the add-on.
                return {status: 0, transient: response.status >= 500 || response.ok,
                        error_message: 'Unexpected response (HTTP ' + response.status + ').'};
            });
        }).then(function (data) {
            if (data.status !== 1) {
                var error = new Error(data.error_message || data.errorMessage || 'Request failed.');
                error.transient = !!data.transient;
                throw error;
            }
            return data;
        });
    }

    /* Retry a request while it fails transiently (panel busy, restarting, network blip),
       waiting a little longer each time; give up after about two minutes. onRetry(error, n)
       lets the caller say it is reconnecting. Errors returned by the add-on are not retried. */
    function retry(request, onRetry, attempts, delay) {
        attempts = attempts === undefined ? 12 : attempts;
        delay = delay || 2000;
        return request().catch(function (error) {
            if (!error.transient || attempts <= 0) { throw error; }
            if (onRetry) { onRetry(error, 13 - attempts); }
            return new Promise(function (resolve) { setTimeout(resolve, delay); }).then(function () {
                return retry(request, onRetry, attempts - 1, Math.min(delay * 1.5, 15000));
            });
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

    window.UA = {api: api, retry: retry, esc: esc, resultRows: resultRows, busy: busy, showError: showError};
})(window);
