"""Fixtures: an administrator, two resellers with one customer each, packages and websites.
Website operations that touch the server (create, suspend, delete) are replaced by fakes that
only change the database, the way the real ones end."""
import contextlib
import json
from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase


class PanelTestCase(TestCase):
    """The panel's apps ship no migrations, so their tables are missing from the test database.
    Create every missing table (outside the test transaction, as sqlite requires) and drop them
    afterwards. Deleting accounts and websites needs all of them for the cascade."""

    @classmethod
    def setUpClass(cls):
        from django.apps import apps
        from django.db import connection
        existing = set(connection.introspection.table_names())
        cls._created_tables = []
        with connection.schema_editor() as editor:
            for model in apps.get_models():
                meta = model._meta
                if meta.managed and not meta.proxy and meta.db_table not in existing:
                    try:
                        editor.create_model(model)
                        cls._created_tables.append(model)
                        existing.add(meta.db_table)
                    except Exception:
                        pass
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        from django.db import connection
        super().tearDownClass()
        with connection.schema_editor() as editor:
            for model in reversed(cls._created_tables):
                try:
                    editor.delete_model(model)
                except Exception:
                    pass


def make_world(test):
    from loginSystem.models import ACL, Administrator
    from packages.models import Package
    from plogical.acl import ACLManager
    from websiteFunctions.models import Websites

    ACLManager.createDefaultACLs()
    admin_acl = ACL.objects.get(name='admin')
    reseller_acl = ACL.objects.get(name='reseller')
    user_acl = ACL.objects.get(name='user')

    def account(name, acl, owner=None, api=1):
        a = Administrator.objects.create(userName=name, password='x', email='%s@example.com' % name,
                                         type=1 if acl == admin_acl else 3, owner=owner or 1, acl=acl,
                                         api=api, initWebsitesLimit=0)
        return a

    test.admin = account('admin', admin_acl, owner=1)
    test.admin.owner = test.admin.pk
    test.admin.save()
    test.res_a = account('reseller_a', reseller_acl, owner=test.admin.pk)
    test.res_b = account('reseller_b', reseller_acl, owner=test.admin.pk)
    test.user_a = account('user_a', user_acl, owner=test.res_a.pk, api=0)
    test.user_b = account('user_b', user_acl, owner=test.res_b.pk, api=0)
    test.pkg_admin = Package.objects.create(admin=test.admin, packageName='Default', diskSpace=1000,
                                            bandwidth=5000)
    test.pkg_a = Package.objects.create(admin=test.res_a, packageName='reseller_a_Gold', diskSpace=2000,
                                        bandwidth=0)

    def site(domain, owner, package, disk=0, bw=0, state=1):
        config = json.dumps({'DiskUsage': disk, 'DiskUsagePercentage': 0, 'bwInMB': bw, 'bwUsage': 0})
        return Websites.objects.create(admin=owner, package=package, domain=domain, adminEmail=owner.email,
                                       phpSelection='PHP 8.1', ssl=1, externalApp=domain[:5] + '1234',
                                       config=config, state=state)

    test.site_a1 = site('a1.example.com', test.user_a, test.pkg_a, disk=120.5, bw=300)
    test.site_a2 = site('a2.example.com', test.user_a, test.pkg_a, disk=10, bw=5)
    test.site_b1 = site('b1.example.com', test.user_b, test.pkg_admin, disk=1, bw=1)


def fake_status(self, userID=None, data=None):
    from loginSystem.models import Administrator
    from plogical.acl import ACLManager
    from websiteFunctions.models import Websites
    acl = ACLManager.loadedACL(userID)
    if ACLManager.currentContextPermission(acl, 'suspendWebsite') == 0 or \
            ACLManager.checkOwnership(data['websiteName'], Administrator.objects.get(pk=userID), acl) != 1:
        return HttpResponse(json.dumps({'websiteStatus': 0, 'error_message': 'denied'}))
    Websites.objects.filter(domain=data['websiteName']).update(state=0 if data['state'] == 'Suspend' else 1)
    return HttpResponse(json.dumps({'websiteStatus': 1, 'error_message': 'None'}))


def fake_create(self, userID=None, data=None, conversionPreflight=None):
    from loginSystem.models import Administrator
    from packages.models import Package
    from websiteFunctions.models import Websites
    owner = Administrator.objects.get(userName=data['websiteOwner'])
    Websites.objects.create(admin=owner, package=Package.objects.get(packageName=data['package']),
                            domain=data['domainName'], adminEmail=data['adminEmail'],
                            phpSelection=data['phpSelection'], ssl=1, externalApp='fake1234', config='{}')
    return HttpResponse(json.dumps({'status': 1, 'createWebSiteStatus': 1, 'tempStatusPath': '/home/cyberpanel/x',
                                    'LinuxUser': 'fake1234'}))


def fake_delete(self, userID=None, data=None):
    from websiteFunctions.models import Websites
    Websites.objects.filter(domain=data['websiteName']).delete()
    return HttpResponse(json.dumps({'status': 1, 'websiteDeleteStatus': 1}))


@contextlib.contextmanager
def fake_server():
    with mock.patch('websiteFunctions.website.WebsiteManager.submitWebsiteStatus', fake_status), \
            mock.patch('websiteFunctions.website.WebsiteManager.submitWebsiteCreation', fake_create), \
            mock.patch('websiteFunctions.website.WebsiteManager.submitWebsiteDeletion', fake_delete):
        yield


def api_post(view, body, token=None, ip='203.0.113.5'):
    extra = {'REMOTE_ADDR': ip}
    if token:
        extra['HTTP_AUTHORIZATION'] = 'Bearer %s' % token
    request = RequestFactory().post('/api/v2/x', data=json.dumps(body), content_type='application/json', **extra)
    request.session = {}
    response = view(request)
    return response.status_code, json.loads(response.content.decode())
