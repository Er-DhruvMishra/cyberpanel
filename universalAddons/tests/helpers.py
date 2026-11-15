"""Shared fixtures for view tests: who is calling, which sites they own, what the policy says."""
import contextlib
import json
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory

from universalAddons import access

OWNED = ('mine.example.com', 'blog.mine.example.com')   # websites/child domains the caller manages
FOREIGN = 'other.example.net'                            # a site of another account


@contextlib.contextmanager
def caller(admin=False, owned=OWNED, policy=None):
    """Patch the panel ACL: an administrator, or a user who owns `owned` (and nothing else)."""
    owned = sorted({d.lower() for d in owned})

    def check_ownership(domain, admin_obj, acl):
        return 1 if acl.get('admin') == 1 or domain in owned else 0

    with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1 if admin else 0}), \
            mock.patch('loginSystem.models.Administrator.objects.get', return_value=SimpleNamespace(pk=7, userName='bob')), \
            mock.patch('universalAddons.access.ACLManager.checkOwnership', side_effect=check_ownership), \
            mock.patch('universalAddons.access.ACLManager.findAllSites', return_value=list(owned)), \
            mock.patch('universalAddons.access.load_policy', return_value=dict(access.DEFAULT_POLICY, **(policy or {}))):
        yield


def post(view, body, session=None, **who):
    """POST `body` as JSON to `view`; returns (status code, parsed body, session)."""
    request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
    request.session = session if session is not None else {'userID': 7}
    with caller(**who):
        response = view(request)
    return response.status_code, json.loads(response.content), request.session


def page(view, **who):
    """GET a page view with httpProc replaced; returns (status code, template values or None)."""
    request = RequestFactory().get('/x')
    request.session = {'userID': 7}
    captured = {}

    class Proc:
        def __init__(self, request, template, data=None, function=None):
            captured.update(data or {}, _template=template, _function=function)

        def render(self):
            from django.http import HttpResponse
            return HttpResponse('page')

    with caller(**who), mock.patch('plogical.httpProc.httpProc', Proc):
        response = view(request)
    return response.status_code, (captured or None)
