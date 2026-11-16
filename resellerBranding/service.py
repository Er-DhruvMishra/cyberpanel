"""Reseller white-label branding: validation, logo checks and resolution.

Resolution (what a page shows):
  * logged in: the account's own branding if it is a reseller, else its owner's branding if the
    owner is a reseller, else the IndiansCloud default. Administrator accounts always get the
    default, and an administrator never inherits a reseller's brand.
  * not logged in (login page): the branding whose hostname matches the request's Host, else
    the default.
"""
import base64
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET

DEFAULT_NAME = 'IndiansCloud'
DEFAULT_TITLE_SUFFIX = ' - IndiansCloud'
MAX_LOGO_BYTES = 256 * 1024
COLOR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')
NAME_RE = re.compile(r'^[^\x00-\x1f\x7f<>"]{1,60}$')
LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
SVG_NS = 'http://www.w3.org/2000/svg'
XLINK_NS = 'http://www.w3.org/1999/xlink'
SVG_ELEMENTS = {
    'svg', 'g', 'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'text',
    'tspan', 'defs', 'linearGradient', 'radialGradient', 'stop', 'clipPath', 'mask', 'title',
    'desc', 'symbol', 'use',
}
SVG_ATTRIBUTE_RE = re.compile(r'^[A-Za-z_:][A-Za-z0-9_.:-]*$')
STYLE_BAD_RE = re.compile(r'url\s*\(\s*[\'"]?\s*(?!#)|expression\s*\(|@import|javascript:|behavior\s*:', re.I)


def default_brand():
    return {
        'name': DEFAULT_NAME, 'title_suffix': DEFAULT_TITLE_SUFFIX, 'logo_url': '',
        'primary_color': '', 'support_url': '', 'support_email': '', 'is_default': True,
    }


def brand_dict(branding):
    if branding is None:
        return default_brand()
    logo_url = ''
    if branding.logo_data and branding.logo_hash:
        from django.urls import reverse
        logo_url = reverse('icBrandLogo', args=[branding.reseller_id, branding.logo_hash])
    return {
        'name': branding.name, 'title_suffix': ' - %s' % branding.name, 'logo_url': logo_url,
        'primary_color': branding.primary_color, 'support_url': branding.support_url,
        'support_email': branding.support_email, 'is_default': False,
    }


# --------------------------------------------------------------------------- accounts

def _is_admin(account):
    from plogical.acl import ACLManager
    try:
        return ACLManager.isAdminACL(account.acl)
    except Exception:
        return False


def is_reseller(account):
    if account is None or _is_admin(account):
        return False
    from provisioning.accounts import permission
    return permission(account, 'resellerCenter')


def branding_for_account(account):
    """The ResellerBranding that applies to ``account`` (user -> reseller -> default=None)."""
    from loginSystem.models import Administrator
    from .models import ResellerBranding
    if account is None or _is_admin(account):
        return None
    chain = [account]
    if account.owner and account.owner != account.pk:
        owner = Administrator.objects.filter(pk=account.owner).first()
        if owner is not None:
            chain.append(owner)
    for candidate in chain:
        if _is_admin(candidate):
            return None
        if is_reseller(candidate):
            branding = ResellerBranding.objects.filter(reseller_id=candidate.pk).first()
            if branding is not None:
                return branding
    return None


def request_hostname(request):
    try:
        host = request.get_host()
    except Exception:
        host = request.META.get('HTTP_HOST', '')
    host = str(host or '').strip().lower()
    if host.startswith('['):
        return ''
    return host.rsplit(':', 1)[0].rstrip('.')


def branding_for_host(hostname):
    from .models import ResellerBranding
    if not hostname:
        return None
    return ResellerBranding.objects.filter(hostname=hostname).first()


def resolve(request):
    """The brand dictionary for a request. Never raises."""
    try:
        from loginSystem.models import Administrator
        user_id = None
        try:
            user_id = request.session.get('userID')
        except Exception:
            user_id = None
        if user_id:
            account = Administrator.objects.filter(pk=user_id).first()
            return brand_dict(branding_for_account(account))
        return brand_dict(branding_for_host(request_hostname(request)))
    except Exception:
        return default_brand()


# --------------------------------------------------------------------------- validation

def clean_name(value):
    value = str(value or '').strip()
    if not NAME_RE.match(value):
        raise ValueError('The brand name must be 1 to 60 characters, without < > or quotes.')
    return value


def clean_color(value):
    value = str(value or '').strip()
    if value and not COLOR_RE.match(value):
        raise ValueError('The primary colour must look like #1a73e8.')
    return value.lower()


def clean_support_url(value):
    from django.core.validators import URLValidator
    from django.core.exceptions import ValidationError
    value = str(value or '').strip()
    if not value:
        return ''
    if len(value) > 200:
        raise ValueError('The support URL is too long.')
    try:
        URLValidator(schemes=['http', 'https'])(value)
    except ValidationError:
        raise ValueError('The support URL must be a full http:// or https:// address.')
    return value


def clean_support_email(value):
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        validate_email(value)
    except ValidationError:
        raise ValueError('Invalid support email address.')
    if len(value) > 100:
        raise ValueError('The support email is too long.')
    return value


def clean_hostname(value):
    value = str(value or '').strip().lower().rstrip('.')
    if not value:
        return None
    if len(value) > 253:
        raise ValueError('The hostname is too long.')
    try:
        ipaddress.ip_address(value)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError('Use a hostname such as panel.example.com, not an IP address.')
    labels = value.split('.')
    if len(labels) < 2 or not all(LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        raise ValueError('Use a full hostname such as panel.example.com.')
    if value in panel_hostnames():
        raise ValueError("This is the panel's own hostname; it keeps the IndiansCloud login page.")
    return value


def panel_hostnames():
    import socket
    names = set()
    for getter in (socket.gethostname, socket.getfqdn):
        try:
            names.add(getter().strip().lower().rstrip('.'))
        except Exception:
            pass
    return {n for n in names if n}


# --------------------------------------------------------------------------- logos

def _local(tag):
    if tag.startswith('{'):
        namespace, _, name = tag[1:].partition('}')
        return namespace, name
    return '', tag


def validate_svg(raw):
    """Reject (not sanitise) anything that is not a plain vector drawing."""
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('The SVG must be UTF-8 text.')
    lowered = text.lower()
    if '<!doctype' in lowered or '<!entity' in lowered:
        raise ValueError('SVG files with a DOCTYPE or entities are not accepted.')
    if 'javascript:' in lowered or '<script' in lowered:
        raise ValueError('SVG files with scripts are not accepted.')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError('The SVG file could not be parsed.')
    namespace, name = _local(root.tag)
    if name != 'svg' or namespace not in ('', SVG_NS):
        raise ValueError('This is not an SVG image.')
    for element in root.iter():
        if not isinstance(element.tag, str):
            raise ValueError('SVG files with processing instructions are not accepted.')
        namespace, name = _local(element.tag)
        if namespace not in ('', SVG_NS) or name not in SVG_ELEMENTS:
            raise ValueError('SVG element <%s> is not accepted; export a plain SVG.' % name[:30])
        for attribute, value in element.attrib.items():
            attr_ns, attr_name = _local(attribute)
            if attr_ns not in ('', XLINK_NS, 'http://www.w3.org/XML/1998/namespace'):
                raise ValueError('SVG attribute %s is not accepted.' % attr_name[:30])
            if not SVG_ATTRIBUTE_RE.match(attr_name) or attr_name.lower().startswith('on'):
                raise ValueError('SVG event attributes are not accepted.')
            if attr_name == 'href' and not value.strip().startswith('#'):
                raise ValueError('SVG links to other files are not accepted.')
            if STYLE_BAD_RE.search(value):
                raise ValueError('SVG styles that load other files are not accepted.')
    return 'image/svg+xml'


def sniff_logo(raw):
    """Return the MIME type of an accepted logo, or raise ValueError."""
    if not raw:
        raise ValueError('Choose a logo file.')
    if len(raw) > MAX_LOGO_BYTES:
        raise ValueError('The logo must be at most %d KB.' % (MAX_LOGO_BYTES // 1024))
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if raw.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    head = raw[:512].lstrip().lower()
    if head.startswith(b'<?xml') or head.startswith(b'<svg') or b'<svg' in head:
        return validate_svg(raw)
    raise ValueError('The logo must be a PNG, JPG or SVG file.')


def store_logo(branding, raw):
    branding.logo_mime = sniff_logo(raw)
    branding.logo_data = base64.b64encode(raw).decode('ascii')
    branding.logo_hash = hashlib.sha256(raw).hexdigest()[:16]
    return branding
