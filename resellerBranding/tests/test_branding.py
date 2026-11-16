import json
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.template.loader import render_to_string
from django.test import RequestFactory

from provisioning.tests.helpers import PanelTestCase, make_world
from resellerBranding import service, views
from resellerBranding.models import ResellerBranding

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64
PLAIN_SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><title>Acme</title>'
             b'<defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs>'
             b'<rect width="10" height="10" fill="url(#g)"/><use href="#g"/></svg>')
BAD_SVGS = {
    'script': b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    'onload': b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>',
    'external href': b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
                     b'<use xlink:href="https://evil.example/x.svg#a"/></svg>',
    'entity': b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg">&a;</svg>',
    'foreignObject': b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>',
    'javascript url': b'<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>',
    'style element': b'<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(x)</style></svg>',
    'style url': b'<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://e.example/a)"/></svg>',
    'image': b'<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AA"/></svg>',
    'html namespace': b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:h="http://www.w3.org/1999/xhtml"><h:p/></svg>',
}


def session_request(path='/x', user=None, host='panel.indianscloud.com', method='get', **kwargs):
    factory = RequestFactory()
    request = getattr(factory, method)(path, HTTP_HOST=host, **kwargs)
    request.session = {'userID': user.pk} if user else {}
    return request


class Resolution(PanelTestCase):
    def setUp(self):
        make_world(self)
        self.brand_a = ResellerBranding.objects.create(reseller_id=self.res_a.pk, name='Acme Hosting',
                                                       primary_color='#aa0011', hostname='panel.acme.example')

    def test_user_gets_resellers_brand(self):
        self.assertEqual(service.resolve(session_request(user=self.user_a))['name'], 'Acme Hosting')

    def test_reseller_gets_own_brand(self):
        brand = service.resolve(session_request(user=self.res_a))
        self.assertEqual((brand['name'], brand['title_suffix'], brand['is_default']),
                         ('Acme Hosting', ' - Acme Hosting', False))

    def test_default_when_no_branding(self):
        for account in (self.user_b, self.res_b, self.admin):
            brand = service.resolve(session_request(user=account))
            self.assertEqual((brand['name'], brand['title_suffix']), ('IndiansCloud', ' - IndiansCloud'))

    def test_admin_stays_indianscloud_even_on_reseller_hostname(self):
        brand = service.resolve(session_request(user=self.admin, host='panel.acme.example'))
        self.assertTrue(brand['is_default'])

    def test_login_page_uses_hostname(self):
        self.assertEqual(service.resolve(session_request(host='panel.acme.example:8090'))['name'], 'Acme Hosting')
        self.assertTrue(service.resolve(session_request(host='other.example'))['is_default'])

    def test_user_whose_owner_is_not_a_reseller(self):
        from loginSystem.models import ACL
        self.res_a.acl = ACL.objects.get(name='user')     # demoted: its branding no longer applies
        self.res_a.save()
        self.assertTrue(service.resolve(session_request(user=self.user_a))['is_default'])

    def test_resolve_never_raises(self):
        with mock.patch('resellerBranding.service.branding_for_account', side_effect=RuntimeError):
            self.assertTrue(service.resolve(session_request(user=self.user_a))['is_default'])


class Validation(PanelTestCase):
    def test_svg_rejections(self):
        for label, svg in BAD_SVGS.items():
            with self.assertRaises(ValueError, msg=label):
                service.sniff_logo(svg)

    def test_accepts_plain_svg_png_jpeg(self):
        self.assertEqual(service.sniff_logo(PLAIN_SVG), 'image/svg+xml')
        self.assertEqual(service.sniff_logo(PNG), 'image/png')
        self.assertEqual(service.sniff_logo(b'\xff\xd8\xff\xe0' + b'\x00' * 20), 'image/jpeg')

    def test_rejects_other_types_and_large_files(self):
        with self.assertRaises(ValueError):
            service.sniff_logo(b'GIF89a' + b'\x00' * 20)
        with self.assertRaises(ValueError):
            service.sniff_logo(PNG + b'\x00' * service.MAX_LOGO_BYTES)

    def test_hostname_and_colour(self):
        self.assertEqual(service.clean_hostname('Panel.Acme.Example.'), 'panel.acme.example')
        for bad in ('localhost', '10.0.0.1', 'bad_host.example.com', '-x.example.com', 'a..b', 'x.123'):
            with self.assertRaises(ValueError, msg=bad):
                service.clean_hostname(bad)
        with mock.patch('resellerBranding.service.panel_hostnames', return_value={'srv.indianscloud.com'}):
            with self.assertRaises(ValueError):
                service.clean_hostname('srv.indianscloud.com')
        self.assertEqual(service.clean_color('#AABBCC'), '#aabbcc')
        for bad in ('red', '#abc', '#aabbcc;x', 'expression(1)'):
            with self.assertRaises(ValueError):
                service.clean_color(bad)
        with self.assertRaises(ValueError):
            service.clean_support_url('javascript:alert(1)')
        with self.assertRaises(ValueError):
            service.clean_name('<b>x</b>')


class SettingsEndpoints(PanelTestCase):
    def setUp(self):
        make_world(self)

    def post(self, view, user, payload):
        request = session_request(user=user, method='post', data=json.dumps({'payload': payload}),
                                  content_type='application/json')
        request._dont_enforce_csrf_checks = True
        return json.loads(view(request).content)

    def test_reseller_saves_own_branding_but_not_hostname(self):
        data = self.post(views.save, self.res_a, {'name': 'Acme', 'primary_color': '#112233',
                                                  'support_url': 'https://help.acme.example',
                                                  'hostname': 'panel.acme.example'})
        self.assertEqual(data['status'], 1, data)
        branding = ResellerBranding.objects.get(reseller_id=self.res_a.pk)
        self.assertEqual((branding.name, branding.hostname), ('Acme', None))

    def test_reseller_cannot_edit_other_reseller(self):
        data = self.post(views.save, self.res_a, {'reseller': 'reseller_b', 'name': 'Hijack'})
        self.assertEqual(data['status'], 0)
        self.assertFalse(ResellerBranding.objects.filter(reseller_id=self.res_b.pk).exists())

    def test_plain_user_has_no_branding(self):
        self.assertEqual(self.post(views.save, self.user_a, {'name': 'Mine'})['status'], 0)

    def test_admin_sets_hostname_unique(self):
        data = self.post(views.save, self.admin, {'reseller': 'reseller_a', 'name': 'Acme', 'hostname': 'panel.acme.example'})
        self.assertEqual(data['hostname'], 'panel.acme.example')
        data = self.post(views.save, self.admin, {'reseller': 'reseller_b', 'name': 'B', 'hostname': 'panel.acme.example'})
        self.assertEqual(data['status'], 0)

    def test_logo_upload_and_serve(self):
        self.post(views.save, self.res_a, {'name': 'Acme'})
        request = session_request(user=self.res_a, method='post', data={'logo': SimpleUploadedFile('l.svg', PLAIN_SVG)})
        request._dont_enforce_csrf_checks = True
        data = json.loads(views.upload_logo(request).content)
        self.assertEqual(data['status'], 1, data)
        branding = ResellerBranding.objects.get(reseller_id=self.res_a.pk)
        response = views.logo(RequestFactory().get('/'), self.res_a.pk, branding.logo_hash)
        self.assertEqual(response['Content-Type'], 'image/svg+xml')
        self.assertIn('sandbox', response['Content-Security-Policy'])
        self.assertEqual(response.content, PLAIN_SVG)

        request = session_request(user=self.res_a, method='post',
                                  data={'logo': SimpleUploadedFile('l.svg', BAD_SVGS['script'])})
        request._dont_enforce_csrf_checks = True
        data = json.loads(views.upload_logo(request).content)
        self.assertEqual(data['status'], 0)
        self.assertEqual(ResellerBranding.objects.get(reseller_id=self.res_a.pk).logo_hash, branding.logo_hash)


class PageRender(PanelTestCase):
    """The base template, login page and the two new pages render, branded and unbranded."""

    def setUp(self):
        make_world(self)
        self.brand = ResellerBranding.objects.create(reseller_id=self.res_a.pk, name='Acme Hosting',
                                                     primary_color='#aa0011', hostname='panel.acme.example',
                                                     support_email='help@acme.example')
        service.store_logo(self.brand, PNG)
        self.brand.save()

    def render(self, template, user=None, host='panel.indianscloud.com', extra=None):
        context = {'admin': 1 if user is self.admin else 0, 'ipAddress': '192.0.2.1'}
        context.update(extra or {})
        return render_to_string(template, context, request=session_request(user=user, host=host))

    def test_tokens_page_default_brand(self):
        html = self.render('provisioning/apiTokens.html', self.user_b,
                           extra={'api_enabled': False, 'max_days': 3650})
        self.assertIn('<title>API Tokens - IndiansCloud</title>', html)
        self.assertIn('indianscloud-logo.svg', html)
        self.assertIn("const brandName = 'IndiansCloud'", html)
        self.assertIn('API access is not enabled', html)
        self.assertNotIn('ic-reseller-brand', html)

    def test_branded_page(self):
        html = self.render('resellerBranding/settings.html', self.user_a, extra={'resellers': ['reseller_a']})
        self.assertIn('<title>Branding - Acme Hosting</title>', html)
        self.assertIn(self.brand.logo_hash, html)
        self.assertIn('--accent-color:#aa0011', html)
        self.assertIn('mailto:help@acme.example', html)
        self.assertNotIn('indianscloud-logo.svg', html)

    def test_login_page_on_reseller_hostname(self):
        html = self.render('loginSystem/login.html', host='panel.acme.example')
        self.assertIn('Login - Acme Hosting', html)
        self.assertIn(self.brand.logo_hash, html)
        self.assertNotIn('indianscloud-logo-reverse.svg', html)
        html = self.render('loginSystem/login.html')
        self.assertIn('Login - IndiansCloud', html)
        self.assertIn('indianscloud-logo-reverse.svg', html)

    def test_views_pick_templates(self):
        from provisioning import panel_views
        captured = {}

        class Proc:
            def __init__(self, request, template, data=None, function=None):
                captured.update(data or {}, _template=template)

            def render(self):
                from django.http import HttpResponse
                return HttpResponse('ok')

        with mock.patch('plogical.httpProc.httpProc', Proc):
            panel_views.tokens_page(session_request(user=self.res_a))
            self.assertEqual(captured['_template'], 'provisioning/apiTokens.html')
            views.settings_page(session_request(user=self.admin))
            self.assertEqual(captured['_template'], 'resellerBranding/settings.html')
            self.assertIn('reseller_a', captured['resellers'])
            response = views.settings_page(session_request(user=self.user_a))
            self.assertIn(b'not authorized', response.content)
