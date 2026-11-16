"""Provider request building and HTTP handling (all HTTP mocked; no network)."""
import json
from unittest import mock

import requests
from django.test import SimpleTestCase

from aiScanner import providers

KEY = 'sk-test-0123456789abcdefghij'


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, raw=None):
        self.status_code = status
        self.headers = headers or {}
        self._raw = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        self.content = self._raw
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._raw), chunk_size):
            yield self._raw[i:i + chunk_size]

    def close(self):
        self.closed = True


class FakeHTTP:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


OPENAI_OK = {'choices': [{'message': {'content': '{"ok": true}'}}], 'usage': {'total_tokens': 42}}


class RequestBuildingTests(SimpleTestCase):
    def test_gemini_request(self):
        cfg = providers.resolve({'provider': 'gemini', 'model': 'models/gemini-3.5-flash-lite'})
        url, headers, body = providers.build_request(cfg, KEY, 'SYS', 'PROMPT', 1000)
        self.assertEqual(url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent')
        self.assertEqual(headers['x-goog-api-key'], KEY)
        self.assertNotIn(KEY, url)
        self.assertEqual(body['systemInstruction']['parts'][0]['text'], 'SYS')
        self.assertEqual(body['contents'][0]['parts'][0]['text'], 'PROMPT')
        self.assertEqual(body['generationConfig']['responseMimeType'], 'application/json')
        self.assertEqual(body['generationConfig']['maxOutputTokens'], 1000)

    def test_gemini_model_cannot_escape_the_path(self):
        for bad in ('../../v1/files', 'gemini?alt=x', 'a/b'):
            with self.assertRaises(providers.ConfigError):
                providers.resolve({'provider': 'gemini', 'model': bad})

    def test_openai_compatible_presets(self):
        expected = {
            'groq': 'https://api.groq.com/openai/v1/chat/completions',
            'openrouter': 'https://openrouter.ai/api/v1/chat/completions',
            'mistral': 'https://api.mistral.ai/v1/chat/completions',
            'cerebras': 'https://api.cerebras.ai/v1/chat/completions',
            'openai': 'https://api.openai.com/v1/chat/completions',
        }
        for name, url_expected in expected.items():
            cfg = providers.resolve({'provider': name})
            url, headers, body = providers.build_request(cfg, KEY, 'SYS', 'P', 500)
            self.assertEqual(url, url_expected, name)
            self.assertEqual(headers['Authorization'], 'Bearer ' + KEY)
            self.assertEqual(body['messages'][0], {'role': 'system', 'content': 'SYS'})
            self.assertEqual(body['messages'][1], {'role': 'user', 'content': 'P'})
            self.assertEqual(body['response_format'], {'type': 'json_object'})

    def test_openai_uses_max_completion_tokens_without_temperature(self):
        cfg = providers.resolve({'provider': 'openai', 'model': 'gpt-5-nano'})
        _, _, body = providers.build_request(cfg, KEY, 'S', 'P', 700)
        self.assertEqual(body['max_completion_tokens'], 700)
        self.assertNotIn('max_tokens', body)
        self.assertNotIn('temperature', body)
        cfg = providers.resolve({'provider': 'groq'})
        _, _, body = providers.build_request(cfg, KEY, 'S', 'P', 700)
        self.assertEqual(body['max_tokens'], 700)
        self.assertEqual(body['temperature'], 0)

    def test_cloudflare_needs_account_id(self):
        with self.assertRaises(providers.ConfigError):
            providers.resolve({'provider': 'cloudflare'})
        with self.assertRaises(providers.ConfigError):
            providers.resolve({'provider': 'cloudflare', 'account_id': '../../evil'})
        cfg = providers.resolve({'provider': 'cloudflare', 'account_id': 'A' * 32})
        url, headers, body = providers.build_request(cfg, KEY, 'S', 'P')
        self.assertEqual(url, 'https://api.cloudflare.com/client/v4/accounts/%s/ai/v1/chat/completions' % ('a' * 32))
        self.assertEqual(body['model'], '@cf/openai/gpt-oss-120b')
        self.assertNotIn('response_format', body)  # JSON mode not offered for gpt-oss there

    def test_anthropic_request(self):
        cfg = providers.resolve({'provider': 'anthropic'})
        url, headers, body = providers.build_request(cfg, KEY, 'SYS', 'P', 900, schema={'type': 'object'})
        self.assertEqual(url, 'https://api.anthropic.com/v1/messages')
        self.assertEqual(headers['x-api-key'], KEY)
        self.assertEqual(headers['anthropic-version'], '2023-06-01')
        self.assertNotIn('Authorization', headers)
        self.assertEqual(body['model'], 'claude-haiku-5-5')
        self.assertEqual(body['system'], 'SYS')
        self.assertEqual(body['max_tokens'], 900)
        self.assertEqual(body['output_config']['format'], {'type': 'json_schema', 'schema': {'type': 'object'}})
        self.assertNotIn('temperature', body)

    def test_custom_endpoint_rules(self):
        cfg = providers.resolve({'provider': 'custom', 'base_url': 'http://127.0.0.1:11434/v1/', 'model': 'qwen2.5-coder:7b'})
        url, headers, _ = providers.build_request(cfg, '', 'S', 'P')
        self.assertEqual(url, 'http://127.0.0.1:11434/v1/chat/completions')
        self.assertNotIn('Authorization', headers)
        for bad in ('http://10.0.0.5/v1', 'ftp://x/v1', 'https://user:pw@host/v1', 'https://host/v1?x=1', ''):
            with self.assertRaises(providers.ConfigError, msg=bad):
                providers.resolve({'provider': 'custom', 'base_url': bad})
        providers.resolve({'provider': 'custom', 'base_url': 'https://llm.example.net/v1'})


class ExtractTests(SimpleTestCase):
    def test_extract_each_kind(self):
        self.assertEqual(providers.extract_text('openai', OPENAI_OK), ('{"ok": true}', 42))
        gem = {'candidates': [{'content': {'parts': [{'text': 'hidden', 'thought': True}, {'text': '{"a":1}'}]}}],
               'usageMetadata': {'totalTokenCount': 9}}
        self.assertEqual(providers.extract_text('gemini', gem), ('{"a":1}', 9))
        ant = {'content': [{'type': 'thinking', 'thinking': ''}, {'type': 'text', 'text': '{"b":2}'}],
               'usage': {'input_tokens': 5, 'output_tokens': 7}, 'stop_reason': 'end_turn'}
        self.assertEqual(providers.extract_text('anthropic', ant), ('{"b":2}', 12))

    def test_extract_rejects_odd_shapes(self):
        for kind, data in (('openai', {}), ('gemini', {'promptFeedback': {'blockReason': 'SAFETY'}}),
                           ('anthropic', {'stop_reason': 'refusal', 'content': []}), ('openai', []),
                           ('openai', {'choices': [{'message': {'content': 5}}]})):
            with self.assertRaises(providers.ProviderError):
                providers.extract_text(kind, data)


class CallTests(SimpleTestCase):
    def cfg(self):
        return providers.resolve({'provider': 'groq'})

    def test_call_uses_timeouts_and_no_redirects(self):
        http = FakeHTTP(FakeResponse(200, OPENAI_OK))
        text, tokens = providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
        self.assertEqual((text, tokens), ('{"ok": true}', 42))
        url, kwargs = http.calls[0]
        self.assertIs(kwargs['allow_redirects'], False)
        self.assertEqual(kwargs['timeout'], (providers.CONNECT_TIMEOUT, providers.READ_TIMEOUT))
        self.assertTrue(kwargs['stream'])

    def test_redirect_is_an_error(self):
        http = FakeHTTP(FakeResponse(302, {}, headers={'Location': 'http://169.254.169.254/'}))
        with self.assertRaises(providers.ProviderError):
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
        self.assertEqual(len(http.calls), 1)

    def test_429_backoff_then_success(self):
        sleeps, limited = [], []
        http = FakeHTTP(FakeResponse(429, {'error': {'message': 'slow down'}}, headers={'retry-after': '3'}),
                        FakeResponse(200, OPENAI_OK))
        text, _ = providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=sleeps.append, on_rate_limit=limited.append)
        self.assertEqual(text, '{"ok": true}')
        self.assertEqual(sleeps, [3.0])
        self.assertEqual(limited, [3.0])

    def test_429_with_long_retry_after_gives_up(self):
        http = FakeHTTP(FakeResponse(429, {}, headers={'retry-after': '3600'}))
        with self.assertRaises(providers.ProviderError) as ctx:
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
        self.assertTrue(ctx.exception.rate_limited)
        self.assertEqual(len(http.calls), 1)

    def test_error_message_never_contains_the_key(self):
        http = FakeHTTP(FakeResponse(401, {'error': {'message': 'Invalid API key %s provided' % KEY}}))
        with self.assertRaises(providers.ProviderError) as ctx:
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
        self.assertNotIn(KEY, ctx.exception.message)
        self.assertIn('401', ctx.exception.message)

    def test_oversized_response_rejected(self):
        http = FakeHTTP(FakeResponse(200, raw=b'x' * (providers.MAX_RESPONSE_BYTES + 10)))
        with self.assertRaises(providers.ProviderError):
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)

    def test_network_errors_are_wrapped(self):
        http = FakeHTTP(requests.exceptions.ConnectionError('boom ' + KEY))
        with self.assertRaises(providers.ProviderError) as ctx:
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
        self.assertNotIn(KEY, ctx.exception.message)

    def test_missing_key(self):
        with self.assertRaises(providers.ProviderError):
            providers.call(self.cfg(), '', 'S', 'P', http=FakeHTTP(), sleep=lambda s: None)

    def test_test_key_is_tiny(self):
        http = FakeHTTP(FakeResponse(200, OPENAI_OK))
        result = providers.test_key(self.cfg(), KEY, http=http, sleep=lambda s: None)
        self.assertTrue(result['ok'])
        body = http.calls[0][1]['json']
        self.assertLessEqual(body['max_tokens'], 512)
        self.assertLess(len(json.dumps(body)), 600)

    def test_no_real_http_in_tests(self):
        with mock.patch('requests.post', side_effect=AssertionError('network used')):
            http = FakeHTTP(FakeResponse(200, OPENAI_OK))
            providers.call(self.cfg(), KEY, 'S', 'P', http=http, sleep=lambda s: None)
