"""DNS tools (/addons/dns-tools/): DNSSEC for zones you own, and editable DNS templates."""
from plogical.acl import ACLManager

from universalAddons import privileged
from universalAddons.access import error, ok, site_api, site_page
from universalAddons.dnstools import service as sv

FEATURE = 'dnstools_for_users'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('dnstools', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _is_reseller(context):
    return not context.is_admin and context.acl.get('resellerCenter') == 1


def _zone(data, context):
    """A zone the caller owns, by the panel's DNS ownership rule (ACLManager.checkOwnershipZone)."""
    zone = sv.check_zone(data.get('zone'))
    try:
        owned = ACLManager.checkOwnershipZone(zone, context.admin_obj, context.acl) == 1
    except Exception:
        owned = False
    if not owned:
        raise PermissionError('You do not manage the zone %s.' % zone)
    return zone


def page(request):
    def values(admin):
        reseller = False
        try:
            reseller = not admin and ACLManager.loadedACL(request.session['userID']).get('resellerCenter') == 1
        except Exception:
            pass
        return {'is_reseller': reseller, 'placeholders': ['{%s}' % p for p in sv.PLACEHOLDERS], 'types': sv.TYPES}
    return site_page(request, 'universalAddons/dnstools.html', FEATURE, values)


@site_api(FEATURE)
def zones(request, data, context):
    names = sorted(set(ACLManager.findAllDNSZones(context.acl, context.user_id)))
    return ok(result={'zones': names, 'is_admin': context.is_admin, 'is_reseller': _is_reseller(context)})


# ----------------------------------------------------------------------------- DNSSEC

@site_api(FEATURE)
def dnssec_status(request, data, context):
    return _call('status', zone=_zone(data, context))


@site_api(FEATURE)
def dnssec_enable(request, data, context):
    return _call('enable', zone=_zone(data, context))


@site_api(FEATURE)
def dnssec_disable(request, data, context):
    zone = _zone(data, context)
    if data.get('confirmDsRemoved') is not True:
        return error('Remove the DS record at your registrar first, wait for it to expire (often 1-2 days), '
                     'then tick the confirmation.', status=400)
    return _call('disable', zone=zone, confirm_ds_removed=True)


@site_api(FEATURE)
def dnssec_rectify(request, data, context):
    return _call('rectify', zone=_zone(data, context))


# ----------------------------------------------------------------------------- templates

def _scope_for(context, data):
    """The template scope the caller may read or write: administrators 'default' (or a reseller's,
    by id); resellers only their own."""
    if context.is_admin:
        scope = str(data.get('scope') or 'default')
        if scope == 'default' or (scope.startswith('reseller:') and scope[9:].isdigit()):
            return scope
        raise ValueError('Unknown template scope.')
    if _is_reseller(context):
        return 'reseller:%d' % int(context.user_id)
    raise PermissionError('Only administrators and resellers have DNS templates.')


def _resellers():
    from loginSystem.models import Administrator
    return {str(a.pk): a.userName for a in Administrator.objects.filter(acl__resellerCenter=1, acl__adminStatus=0)}


@site_api(FEATURE)
def templates(request, data, context):
    scope = _scope_for(context, data)
    stored = sv.load_templates()
    if scope == 'default':
        template = stored['default']
    else:
        template = stored['resellers'].get(scope[9:])
    result = {'scope': scope, 'template': template, 'fixed': {'records': sv.DEFAULT_RECORDS},
              'placeholders': list(sv.PLACEHOLDERS), 'types': list(sv.TYPES)}
    if context.is_admin:
        try:
            names = _resellers()
        except Exception:
            names = {}
        result.update(ipv6=stored['ipv6'], resellers=[{'id': k, 'name': names.get(k, '#' + k)}
                                                      for k in sorted(set(names) | set(stored['resellers']), key=int)],
                      reseller_templates=sorted(stored['resellers']))
    return ok(result=result)


@site_api(FEATURE)
def template_save(request, data, context):
    scope = _scope_for(context, data)
    template = data.get('template')
    if template is not None:
        template = sv.validate_template(template)
    ipv6 = None
    if context.is_admin and scope == 'default' and 'ipv6' in data:
        ipv6 = sv.check_ipv6(data.get('ipv6'))
    return _call('save_template', scope=scope, template=template, ipv6=ipv6)


@site_api(FEATURE)
def template_preview(request, data, context):
    _scope_for(context, data)
    template = sv.validate_template(data.get('template'))
    domain = sv.check_zone(data.get('zone') or 'example.com')
    values = sv.zone_values(domain, sv.machine_ip() or '192.0.2.10', sv.load_templates()['ipv6'] or '')
    return ok(result={'records': sv.render_template(template, values), 'values': values})


# ----------------------------------------------------------------------------- apply to an existing zone

def _applicable(context, data):
    """The saved template the caller would apply: the given scope for administrators, else the one
    that applies to the caller's new zones (their own or their reseller's, else the default)."""
    stored = sv.load_templates()
    if context.is_admin:
        scope = str(data.get('scope') or 'default')
        if scope == 'default':
            template = stored['default']
        elif scope.startswith('reseller:'):
            template = stored['resellers'].get(scope[9:])
        else:
            template = None
    else:
        template, scope = sv.template_for(stored, context.user_id, getattr(context.admin_obj, 'owner', None))
    if not template:
        raise ValueError('No template is saved for this choice; the panel uses its fixed records.')
    return sv.validate_template(template), stored['ipv6']


def _zone_records(zone):
    from dns.models import Domains, Records
    domain = Domains.objects.get(name=zone)
    rows = Records.objects.filter(domain_id=domain.id)
    return domain, [{'id': r.id, 'name': (r.name or '').lower(), 'type': r.type, 'content': r.content or '',
                     'ttl': r.ttl, 'prio': r.prio or 0} for r in rows]


def _plan(data, context):
    zone = _zone(data, context)
    mode = data.get('mode')
    template, ipv6 = _applicable(context, data)
    rendered = sv.render_template(template, sv.zone_values(zone, sv.machine_ip(), ipv6))
    domain, existing = _zone_records(zone)
    return zone, domain, sv.plan_apply(existing, rendered, mode)


@site_api(FEATURE)
def apply_preview(request, data, context):
    zone, _, plan = _plan(data, context)
    return ok(result=dict(plan, zone=zone))


@site_api(FEATURE)
def apply(request, data, context):
    zone, domain, plan = _plan(data, context)
    if data.get('mode') == 'replace' and plan['remove'] and data.get('confirm') is not True:
        return error('Confirm that %d record(s) will be removed.' % len(plan['remove']), status=400)
    from dns.models import Records
    for record in plan['remove']:
        Records.objects.filter(id=record['id'], domain_id=domain.id).exclude(type__in=sv.PROTECTED).delete()
    for record in plan['add']:
        Records(domainOwner=domain, domain_id=domain.id, name=record['name'], type=record['type'],
                content=record['content'], ttl=record['ttl'], prio=record['prio'], disabled=0, auth=1).save()
    if plan['add'] or plan['remove']:
        try:
            from plogical.dnsUtilities import DNS
            DNS.incrementSOASerial(domain)
        except Exception:
            pass
    return ok(result={'zone': zone, 'added': len(plan['add']), 'removed': len(plan['remove']),
                      'skipped': plan['skipped']})
