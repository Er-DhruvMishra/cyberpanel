"""Pluggable AI providers for the IndiansCloud AI Scanner.

Three request shapes cover every supported service:

* ``gemini``     Google Gemini API, ``models/{model}:generateContent`` (x-goog-api-key)
* ``openai``     any OpenAI-compatible ``/chat/completions`` endpoint (Bearer key):
                 Groq, OpenRouter, Mistral, Cerebras, Cloudflare Workers AI, OpenAI,
                 and custom/self-hosted servers such as Ollama
* ``anthropic``  Anthropic Messages API (x-api-key + anthropic-version)

All HTTP goes through ``requests`` with timeouts, ``allow_redirects=False`` and a
response size cap.  Keys are only ever placed in headers, never in URLs or logs.
"""
import ipaddress
import json
import re
import time
from urllib.parse import quote, urlsplit

import requests

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 90
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_ATTEMPTS = 3
MAX_BACKOFF_SECONDS = 60

ANTHROPIC_VERSION = '2023-06-01'

# kind: request shape.  base_url: fixed endpoint ('' = admin supplies one).
# json_mode: send the provider's JSON-mode switch by default.
PRESETS = {
    'cloudflare': {
        'label': 'Cloudflare Workers AI (free daily allocation, no training on your data)',
        'kind': 'openai',
        'base_url': 'https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1',
        'needs_account_id': True,
        'default_model': '@cf/openai/gpt-oss-120b',
        'models': ['@cf/openai/gpt-oss-120b', '@cf/openai/gpt-oss-20b', '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
                   '@cf/qwen/qwen2.5-coder-32b-instruct'],
        'json_mode': False,
        'key_url': 'https://dash.cloudflare.com/profile/api-tokens',
        'trains_on_free_tier': False,
    },
    'groq': {
        'label': 'Groq (free tier, OpenAI-compatible)',
        'kind': 'openai',
        'base_url': 'https://api.groq.com/openai/v1',
        'default_model': 'openai/gpt-oss-120b',
        'models': ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'llama-3.3-70b-versatile', 'llama-3.1-8b-instant'],
        'json_mode': True,
        'key_url': 'https://console.groq.com/keys',
        'trains_on_free_tier': None,
    },
    'gemini': {
        'label': 'Google Gemini API (free tier: Google may use and human-review prompts)',
        'kind': 'gemini',
        'base_url': 'https://generativelanguage.googleapis.com/v1beta',
        'default_model': 'gemini-3.5-flash-lite',
        'models': ['gemini-3.5-flash-lite', 'gemini-3.1-flash-lite', 'gemini-3.6-flash', 'gemini-3.8-flash'],
        'json_mode': True,
        'key_url': 'https://aistudio.google.com/apikey',
        'trains_on_free_tier': True,
    },
    'openrouter': {
        'label': 'OpenRouter (":free" models; data policy depends on the routed provider)',
        'kind': 'openai',
        'base_url': 'https://openrouter.ai/api/v1',
        'default_model': 'openai/gpt-oss-120b',
        'models': [],
        'json_mode': True,
        'key_url': 'https://openrouter.ai/keys',
        'trains_on_free_tier': True,
    },
    'mistral': {
        'label': 'Mistral La Plateforme (free mode may train unless you opt out)',
        'kind': 'openai',
        'base_url': 'https://api.mistral.ai/v1',
        'default_model': 'mistral-small-latest',
        'models': ['mistral-small-latest', 'codestral-latest', 'mistral-large-latest'],
        'json_mode': True,
        'key_url': 'https://console.mistral.ai/api-keys',
        'trains_on_free_tier': True,
    },
    'cerebras': {
        'label': 'Cerebras Inference (free trial, OpenAI-compatible)',
        'kind': 'openai',
        'base_url': 'https://api.cerebras.ai/v1',
        'default_model': 'gpt-oss-120b',
        'models': ['gpt-oss-120b', 'qwen-3.8-27b'],
        'json_mode': True,
        'key_url': 'https://cloud.cerebras.ai',
        'trains_on_free_tier': None,
    },
    'openai': {
        'label': 'OpenAI (paid; API data not used for training by default)',
        'kind': 'openai',
        'base_url': 'https://api.openai.com/v1',
        'default_model': 'gpt-5-nano',
        'models': ['gpt-5-nano', 'gpt-5-mini'],
        'json_mode': True,
        'token_param': 'max_completion_tokens',
        'send_temperature': False,
        'key_url': 'https://platform.openai.com/api-keys',
        'trains_on_free_tier': False,
    },
    'anthropic': {
        'label': 'Anthropic Claude (paid; API data not used for training)',
        'kind': 'anthropic',
        'base_url': 'https://api.anthropic.com/v1',
        'default_model': 'claude-haiku-5-5',
        'models': ['claude-haiku-5-5', 'claude-sonnet-5-5'],
        'json_mode': True,
        'key_url': 'https://platform.claude.com/settings/keys',
        'trains_on_free_tier': False,
    },
    'custom': {
        'label': 'Custom OpenAI-compatible endpoint (self-hosted, e.g. Ollama)',
        'kind': 'openai',
        'base_url': '',
        'default_model': 'qwen2.5-coder:7b',
        'models': [],
        'json_mode': True,
        'key_optional': True,
        'admin_only': True,
        'key_url': '',
        'trains_on_free_tier': False,
    },
}

_MODEL_RE = re.compile(r'^[A-Za-z0-9@._:/+-]{1,128}$')
_GEMINI_MODEL_RE = re.compile(r'^[A-Za-z0-9._-]{1,96}$')
_ACCOUNT_RE = re.compile(r'^[0-9a-fA-F]{32}$')
_KEY_RE = re.compile(r'^[\x21-\x7e]{8,512}$')


class ProviderError(Exception):
    """A provider call failed.  ``message`` never contains the API key."""

    def __init__(self, message, status=None, retry_after=None, rate_limited=False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.retry_after = retry_after
        self.rate_limited = rate_limited


class ConfigError(ValueError):
    pass


def _loopback(host):
    if host in ('localhost',):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(url):
    """https:// URLs, or http:// only to loopback (a local Ollama).  No credentials, query or fragment."""
    url = (url or '').strip().rstrip('/')
    parts = urlsplit(url)
    if parts.scheme not in ('https', 'http') or not parts.hostname:
        raise ConfigError('Base URL must start with https://')
    if parts.scheme == 'http' and not _loopback(parts.hostname):
        raise ConfigError('Plain http:// is only allowed for a local server (127.0.0.1 or localhost).')
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError('Base URL must not contain credentials, a query string or a fragment.')
    return url


def validate_model(model, kind):
    model = (model or '').strip()
    if kind == 'gemini' and model.startswith('models/'):
        model = model[len('models/'):]
    pattern = _GEMINI_MODEL_RE if kind == 'gemini' else _MODEL_RE
    if not pattern.match(model) or '..' in model:
        raise ConfigError('Invalid model id.')
    return model


def validate_key(key):
    if not _KEY_RE.match(key or ''):
        raise ConfigError('The API key looks invalid (printable characters only, 8-512 long).')
    return key


def resolve(slot):
    """Turn a stored provider slot into a ready-to-call config (raises ConfigError)."""
    provider = (slot or {}).get('provider')
    preset = PRESETS.get(provider)
    if not preset:
        raise ConfigError('Unknown provider.')
    kind = preset['kind']
    base = preset['base_url']
    if provider == 'custom':
        base = validate_base_url(slot.get('base_url'))
    elif preset.get('needs_account_id'):
        account = (slot.get('account_id') or '').strip()
        if not _ACCOUNT_RE.match(account):
            raise ConfigError('Cloudflare needs your 32-character account ID.')
        base = base.format(account_id=account.lower())
    model = validate_model(slot.get('model') or preset['default_model'], kind)
    json_mode = slot.get('json_mode')
    if json_mode is None:
        json_mode = preset.get('json_mode', False)
    return {
        'provider': provider, 'kind': kind, 'base_url': base, 'model': model,
        'json_mode': bool(json_mode),
        'token_param': preset.get('token_param', 'max_tokens'),
        'send_temperature': preset.get('send_temperature', True),
        'key_optional': preset.get('key_optional', False),
    }


# ---------------------------------------------------------------------------
# Request building (pure functions, unit tested per provider)
# ---------------------------------------------------------------------------

def build_request(cfg, api_key, system, prompt, max_output_tokens=2048, schema=None):
    """Return (url, headers, json_body) for one classification request."""
    kind = cfg['kind']
    if kind == 'gemini':
        url = '%s/models/%s:generateContent' % (cfg['base_url'], quote(cfg['model'], safe='.-_'))
        headers = {'Content-Type': 'application/json', 'x-goog-api-key': api_key}
        generation = {'maxOutputTokens': int(max_output_tokens)}
        if cfg.get('json_mode'):
            generation['responseMimeType'] = 'application/json'
        body = {
            'systemInstruction': {'parts': [{'text': system}]},
            'contents': [{'role': 'user', 'parts': [{'text': prompt}]}],
            'generationConfig': generation,
        }
        return url, headers, body

    if kind == 'anthropic':
        url = cfg['base_url'] + '/messages'
        headers = {'Content-Type': 'application/json', 'x-api-key': api_key,
                   'anthropic-version': ANTHROPIC_VERSION}
        body = {
            'model': cfg['model'],
            'max_tokens': int(max_output_tokens),
            'system': system,
            'messages': [{'role': 'user', 'content': prompt}],
            'output_config': {'effort': 'low'},
        }
        if cfg.get('json_mode') and schema:
            body['output_config']['format'] = {'type': 'json_schema', 'schema': schema}
        return url, headers, body

    if kind == 'openai':
        url = cfg['base_url'] + '/chat/completions'
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = 'Bearer ' + api_key
        body = {
            'model': cfg['model'],
            'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}],
            cfg.get('token_param', 'max_tokens'): int(max_output_tokens),
        }
        if cfg.get('send_temperature', True):
            body['temperature'] = 0
        if cfg.get('json_mode'):
            body['response_format'] = {'type': 'json_object'}
        return url, headers, body

    raise ConfigError('Unknown provider kind.')


def extract_text(kind, data):
    """Pull the model's text and token usage out of a provider response body."""
    if not isinstance(data, dict):
        raise ProviderError('Unexpected response from the provider.')
    try:
        if kind == 'gemini':
            candidates = data.get('candidates') or []
            if not candidates:
                reason = (data.get('promptFeedback') or {}).get('blockReason')
                raise ProviderError('The provider returned no answer%s.' % (' (%s)' % reason if reason else ''))
            parts = (candidates[0].get('content') or {}).get('parts') or []
            text = ''.join(p.get('text', '') for p in parts if isinstance(p, dict) and not p.get('thought'))
            tokens = int((data.get('usageMetadata') or {}).get('totalTokenCount') or 0)
        elif kind == 'anthropic':
            if data.get('stop_reason') == 'refusal':
                raise ProviderError('The model declined to classify this content.')
            blocks = data.get('content') or []
            text = ''.join(b.get('text', '') for b in blocks if isinstance(b, dict) and b.get('type') == 'text')
            usage = data.get('usage') or {}
            tokens = int(usage.get('input_tokens') or 0) + int(usage.get('output_tokens') or 0)
        else:
            choices = data.get('choices') or []
            if not choices:
                raise ProviderError('The provider returned no answer.')
            message = choices[0].get('message') or {}
            text = message.get('content') or ''
            if isinstance(text, list):
                text = ''.join(p.get('text', '') for p in text if isinstance(p, dict))
            tokens = int((data.get('usage') or {}).get('total_tokens') or 0)
    except (AttributeError, TypeError, ValueError):
        raise ProviderError('Unexpected response from the provider.')
    if not isinstance(text, str):
        raise ProviderError('Unexpected response from the provider.')
    return text, max(tokens, 0)


def _scrub(text, api_key):
    text = str(text or '')
    if api_key:
        text = text.replace(api_key, '[key]')
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', text)
    return text[:300]


def _error_message(response, api_key):
    detail = ''
    try:
        data = json.loads(response.content[:65536].decode('utf-8', 'replace'))
        err = data.get('error') if isinstance(data, dict) else None
        if isinstance(err, dict):
            detail = err.get('message') or err.get('type') or ''
        elif isinstance(err, str):
            detail = err
        elif isinstance(data, dict) and isinstance(data.get('errors'), list) and data['errors']:
            first = data['errors'][0]
            detail = first.get('message', '') if isinstance(first, dict) else str(first)
    except (ValueError, AttributeError):
        detail = ''
    message = 'HTTP %s from the provider' % response.status_code
    if detail:
        message += ': ' + detail
    return _scrub(message, api_key)


def _retry_after(response):
    value = response.headers.get('retry-after') or response.headers.get('Retry-After')
    try:
        return max(0.0, min(float(value), 3600.0))
    except (TypeError, ValueError):
        return None


def _read_body(response):
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=65536):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise ProviderError('The provider response was too large.')
        chunks.append(chunk)
    return b''.join(chunks)


def call(cfg, api_key, system, prompt, max_output_tokens=2048, schema=None,
         http=requests, sleep=time.sleep, on_rate_limit=None):
    """Send one request; retry 429/5xx with backoff.  Returns (text, tokens)."""
    if not api_key and not cfg.get('key_optional'):
        raise ProviderError('No API key is configured for this provider.')
    url, headers, body = build_request(cfg, api_key, system, prompt, max_output_tokens, schema)
    last = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = http.post(url, headers=headers, json=body, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                                 allow_redirects=False, stream=True)
        except requests.exceptions.Timeout:
            last = ProviderError('The provider did not answer in time.')
            sleep(min(2 ** attempt * 2, MAX_BACKOFF_SECONDS))
            continue
        except requests.exceptions.RequestException as exc:
            raise ProviderError(_scrub('Could not reach the provider: %s' % exc.__class__.__name__, api_key))
        try:
            status = response.status_code
            if 300 <= status < 400:
                raise ProviderError('The provider answered with a redirect; check the base URL.', status=status)
            if status == 429 or status >= 500:
                wait = _retry_after(response)
                last = ProviderError(_error_message(response, api_key), status=status, retry_after=wait,
                                     rate_limited=(status == 429))
                if status == 429 and on_rate_limit:
                    on_rate_limit(wait)
                if attempt + 1 < MAX_ATTEMPTS and (wait is None or wait <= MAX_BACKOFF_SECONDS):
                    sleep(wait if wait is not None else min(2 ** attempt * 5, MAX_BACKOFF_SECONDS))
                    continue
                raise last
            if status >= 400:
                raise ProviderError(_error_message(response, api_key), status=status)
            raw = _read_body(response)
        finally:
            try:
                response.close()
            except Exception:
                pass
        try:
            data = json.loads(raw.decode('utf-8', 'replace'))
        except ValueError:
            raise ProviderError('The provider returned invalid JSON.')
        return extract_text(cfg['kind'], data)
    raise last or ProviderError('The provider call failed.')


def test_key(cfg, api_key, http=requests, sleep=time.sleep):
    """A tiny request that proves the key, model and endpoint work."""
    text, tokens = call(cfg, api_key, 'Reply with JSON only.', 'Return exactly {"ok": true}',
                        max_output_tokens=512, schema=TEST_SCHEMA, http=http, sleep=sleep)
    return {'ok': True, 'tokens': tokens, 'reply_preview': _scrub(text, api_key)[:60]}


TEST_SCHEMA = {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok'],
               'additionalProperties': False}
