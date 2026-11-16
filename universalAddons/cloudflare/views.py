"""Cloudflare add-on endpoints.

Every account (administrator, reseller, user) works with its own Cloudflare API token and sees
the zones that token can access; non-administrators only once the administrator opens the add-on
to users (switch cloudflare_for_users). Administrators may also use a server-wide token, which is
never available to other accounts. A zone may be linked to a panel site the caller manages.

Request bodies keep free-form values (record content, URLs, the token) inside the nested `input`
object: CyberPanel's secMiddleware screens top-level strings for characters like ':' that IPv6
addresses and URLs need. Every value is validated in client.py before it reaches Cloudflare.
"""
from universalAddons import privileged
from universalAddons.access import error, ok, owned_sites, site_api, site_page
from universalAddons.cloudflare import client as cf
from universalAddons.cloudflare import service
from universalAddons.cloudflare.client import CloudflareError

FEATURE = 'cloudflare_for_users'


def page(request):
    return site_page(request, 'universalAddons/cloudflare.html', FEATURE,
                     lambda admin: {'permissions': cf.TOKEN_PERMISSIONS})


def api(view):
    """site_api, plus Cloudflare errors turned into a JSON error (429 kept as 429)."""
    def wrapped(request, data, context):
        try:
            return view(request, data, context)
        except CloudflareError as exc:
            return error(str(exc), status=429 if exc.status == 429 else 400,
                         **({'retry_after': exc.retry_after} if exc.retry_after else {}))
    wrapped.__name__ = view.__name__
    wrapped.__doc__ = view.__doc__
    return site_api(FEATURE)(wrapped)


def _input(data):
    value = data.get('input', {})
    if not isinstance(value, dict):
        raise CloudflareError('Invalid request.')
    return value


def _source(data, context):
    """(account key, label) of the token to use: the caller's own, or the server token for admins."""
    if data.get('source') == 'server':
        if not context.is_admin:
            raise PermissionError('The server-wide token is for administrators only.')
        return service.SERVER_KEY, 'server'
    return service.account_key(context.user_id), 'own'


def _client(key):
    return service.client_for(key)


def _zone(key, zone):
    zone = cf.zone_id(zone)
    return service.cached(key, 'zone:' + zone, lambda: _client(key).zone(zone))


def _changed(context, key, source, zone, action, detail=None):
    service.cache_clear(key, zone)
    service.audit(context, zone, action, detail, source)


# ------------------------------------------------------------------------------------- tokens

@api
def state(request, data, context):
    own = service.account_key(context.user_id)
    result = {'is_admin': context.is_admin, 'token': service.token_state(own),
              'links': service.links(context.user_id),
              'sites': owned_sites(context) if not context.is_admin else _all_sites(),
              'server_ip': service.server_ip()}
    if context.is_admin:
        result['server_token'] = service.token_state(service.SERVER_KEY)
    return ok(result=result)


def _all_sites():
    try:
        from websiteFunctions.models import ChildDomains, Websites
        names = list(Websites.objects.values_list('domain', flat=True)) + \
            list(ChildDomains.objects.values_list('domain', flat=True))
        return sorted({n.lower() for n in names})
    except Exception:
        return []


@api
def token_save(request, data, context):
    key, source = _source(data, context)
    status = service.save_token(key, _input(data).get('token'))
    service.audit(context, '', 'token saved', status.get('status'), source)
    return ok(result={'token': service.token_state(key)})


@api
def token_forget(request, data, context):
    key, source = _source(data, context)
    service.forget_token(key)
    service.audit(context, '', 'token removed', None, source)
    return ok(result={'token': service.token_state(key)})


@api
def token_verify(request, data, context):
    key, _ = _source(data, context)
    status = service.verify(key)
    service.store_verify(key, status)
    return ok(result={'token': service.token_state(key)})


# -------------------------------------------------------------------------------------- zones

@api
def zones(request, data, context):
    key, _ = _source(data, context)
    found = service.cached(key, 'zones', lambda: _client(key).zones())
    linked = service.links(context.user_id)
    return ok(result={'zones': [{
        'id': z.get('id'), 'name': z.get('name'), 'status': z.get('status'),
        'plan': (z.get('plan') or {}).get('name'), 'paused': z.get('paused'),
        'site': linked.get(z.get('id') or '')} for z in found if cf.ID_RE.match(str(z.get('id', '')))]})


@api
def overview(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    linked = service.links(context.user_id).get(zone['id'])
    ns = service.cached(key, 'ns:' + zone['id'], lambda: service.ns_check(zone), ttl=300)
    return ok(result={
        'id': zone['id'], 'name': zone.get('name'), 'status': zone.get('status'), 'paused': zone.get('paused'),
        'type': zone.get('type'), 'plan': (zone.get('plan') or {}).get('name'),
        'name_servers': zone.get('name_servers') or [], 'original_name_servers': zone.get('original_name_servers') or [],
        'ns': ns, 'site': linked})


@api
def link(request, data, context):
    """Link a zone to one of the caller's sites (the site must be the zone name or inside it)."""
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    site = str(_input(data).get('site', '') or '').strip().lower()
    if site:
        site = cf.hostname(site, 'site')
        context.require_site(site)
        if not service.site_in_zone(site, zone.get('name', '')):
            raise CloudflareError('%s is not inside the zone %s.' % (site, zone.get('name')))
    result = service.set_link(context.user_id, zone['id'], site)
    service.audit(context, zone['id'], 'link' if site else 'unlink', site, source)
    return ok(result={'links': result})


def _linked_site(context, zone):
    site = service.links(context.user_id).get(zone['id'])
    if not site:
        raise CloudflareError('Link this zone to one of your sites first.')
    context.require_site(site)   # still yours?
    return site


# ---------------------------------------------------------------------------------------- DNS

@api
def dns_list(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    records = service.cached(key, 'dns:' + zone['id'], lambda: _client(key).dns_records(zone['id']))
    return ok(result={'records': [{
        'id': r.get('id'), 'type': r.get('type'), 'name': r.get('name'), 'content': r.get('content'),
        'data': r.get('data'), 'ttl': r.get('ttl'), 'proxied': r.get('proxied'), 'proxiable': r.get('proxiable'),
        'priority': r.get('priority'), 'comment': r.get('comment')} for r in records],
        'types': cf.RECORD_TYPES})


@api
def dns_save(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    body = cf.validate_record(_input(data).get('record'), zone['name'])
    rid = data.get('record_id')
    if rid:
        result = _client(key).dns_update(zone['id'], cf.record_id(rid), body)
        action = 'dns update'
    else:
        result = _client(key).dns_create(zone['id'], body)
        action = 'dns create'
    _changed(context, key, source, zone['id'], action, '%s %s' % (body['type'], body['name']))
    return ok(result={'id': (result or {}).get('id')})


@api
def dns_delete(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    rid = cf.record_id(data.get('record_id'))
    _client(key).dns_delete(zone['id'], rid)
    _changed(context, key, source, zone['id'], 'dns delete', rid)
    return ok()


@api
def dns_proxied(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    rid = cf.record_id(data.get('record_id'))
    if data.get('proxied') not in (True, False):
        raise CloudflareError('Invalid value.')
    _client(key).dns_patch(zone['id'], rid, {'proxied': data['proxied']})
    _changed(context, key, source, zone['id'], 'dns proxied %s' % ('on' if data['proxied'] else 'off'), rid)
    return ok()


def _import_rows(key, context, zone):
    site = _linked_site(context, zone)
    existing = _client(key).dns_records(zone['id'])
    return site, service.import_preview(site, zone['name'], existing)


@api
def dns_import_preview(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    site, rows = _import_rows(key, context, zone)
    return ok(result={'site': site, 'rows': [{k: v for k, v in r.items() if k != 'body'} for r in rows]})


@api
def dns_import_apply(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    wanted = _input(data).get('keys')
    if not isinstance(wanted, list) or not wanted or not all(isinstance(k, str) for k in wanted):
        raise CloudflareError('Choose the records to import.')
    site, rows = _import_rows(key, context, zone)
    created, failed = 0, []
    for row in rows:
        if row['action'] == 'create' and row['key'] in wanted:
            try:
                _client(key).dns_create(zone['id'], row['body'])
                created += 1
            except CloudflareError as exc:
                if exc.status == 429:
                    failed.append('%s %s: rate limited, stopped' % (row['type'], row['name']))
                    break
                failed.append('%s %s: %s' % (row['type'], row['name'], exc))
    _changed(context, key, source, zone['id'], 'dns import', '%d records from %s' % (created, site))
    return ok(result={'created': created, 'failed': failed})


@api
def point_here(request, data, context):
    """Create or update the A record of a name so it points at this server."""
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    ip = service.server_ip()
    if not ip:
        raise CloudflareError("This server's IPv4 address is unknown (/etc/cyberpanel/machineIP).")
    name = cf.record_name(_input(data).get('name', '@'), zone['name'])
    if not context.is_admin:
        site = _linked_site(context, zone)
        if not service.site_in_zone(name, site):
            raise PermissionError('You can point only %s and names below it here.' % site)
    proxied = data.get('proxied') is True
    records = _client(key).dns_records(zone['id'])
    same = [r for r in records if (r.get('name') or '').lower() == name]
    if any(r.get('type') == 'CNAME' for r in same):
        raise CloudflareError('%s is a CNAME; delete it first.' % name)
    body = {'type': 'A', 'name': name, 'content': ip, 'ttl': 1, 'proxied': proxied}
    a_records = [r for r in same if r.get('type') == 'A']
    if a_records:
        _client(key).dns_update(zone['id'], cf.record_id(a_records[0]['id']), body)
    else:
        _client(key).dns_create(zone['id'], body)
    _changed(context, key, source, zone['id'], 'point to this server', '%s -> %s' % (name, ip))
    return ok(result={'name': name, 'ip': ip, 'updated': bool(a_records)})


# ------------------------------------------------------------------------------- cache & settings

@api
def purge(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    if data.get('everything') is True:
        _client(key).purge(zone['id'])
        detail = 'everything'
    else:
        urls = cf.validate_purge_urls(_input(data).get('urls'), zone['name'])
        _client(key).purge(zone['id'], urls)
        detail = '%d URLs' % len(urls)
    service.audit(context, zone['id'], 'purge cache', detail, source)
    return ok()


@api
def settings(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    found = service.cached(key, 'settings:' + zone['id'], lambda: _client(key).settings(zone['id']))
    values = {}
    for item in found or []:
        if isinstance(item, dict) and item.get('id') in cf.SETTINGS:
            values[item['id']] = {'value': item.get('value'), 'editable': item.get('editable', True)}
    return ok(result={'values': values, 'groups': cf.SETTING_GROUPS,
                      'choices': {k: list(v) for k, v in cf.SETTINGS.items()}})


@api
def setting_set(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    name = str(data.get('setting', ''))
    value = cf.validate_setting(name, data.get('value'))
    _client(key).set_setting(zone['id'], name, value)
    _changed(context, key, source, zone['id'], 'setting %s' % name, value)
    return ok(result={'setting': name, 'value': value})


@api
def under_attack(request, data, context):
    """Under Attack mode on, or off again (back to the level saved when it was turned on, else medium)."""
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    if data.get('enable') not in (True, False):
        raise CloudflareError('Invalid value.')
    restore = cf.validate_setting('security_level', data.get('restore') or 'medium')
    if restore == 'under_attack':
        restore = 'medium'
    value = 'under_attack' if data['enable'] else restore
    _client(key).set_setting(zone['id'], 'security_level', value)
    _changed(context, key, source, zone['id'], 'under attack %s' % ('on' if data['enable'] else 'off'), value)
    return ok(result={'value': value})


# ------------------------------------------------------------------------------- IP access rules

@api
def rules(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    found = service.cached(key, 'rules:' + zone['id'], lambda: _client(key).access_rules(zone['id']))
    return ok(result={'rules': [{
        'id': r.get('id'), 'mode': r.get('mode'), 'target': (r.get('configuration') or {}).get('target'),
        'value': (r.get('configuration') or {}).get('value'), 'notes': r.get('notes'),
        'scope': (r.get('scope') or {}).get('type')} for r in found or []]})


@api
def rule_add(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    rule = cf.validate_access_rule(_input(data).get('rule'))
    _client(key).access_rule_add(zone['id'], rule)
    _changed(context, key, source, zone['id'], 'access rule %s' % rule['mode'], rule['configuration']['value'])
    return ok()


@api
def rule_delete(request, data, context):
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    rid = cf.record_id(data.get('rule_id'))
    _client(key).access_rule_delete(zone['id'], rid)
    _changed(context, key, source, zone['id'], 'access rule delete', rid)
    return ok()


# ----------------------------------------------------------------------------------- analytics

@api
def analytics(request, data, context):
    key, _ = _source(data, context)
    zone = _zone(key, data.get('zone'))
    range_key = str(data.get('range', '24h'))
    if range_key not in cf.ANALYTICS_RANGES:
        raise CloudflareError('Choose 24h, 7d or 30d.')
    result = service.cached(key, 'analytics:%s:%s' % (zone['id'], range_key),
                            lambda: _client(key).analytics(zone['id'], range_key), ttl=60)
    return ok(result=dict(result, range=range_key))


# ---------------------------------------------------------------------------- origin certificate

@api
def origin_cert(request, data, context):
    """Create a 15-year Cloudflare Origin CA certificate for the linked site and install it."""
    key, source = _source(data, context)
    zone = _zone(key, data.get('zone'))
    site = _linked_site(context, zone)
    hostnames = [site, '*.' + site]
    key_pem, csr = service.origin_key_and_csr(hostnames)
    cert = _client(key).origin_certificate(hostnames, csr) or {}
    cert_pem = cert.get('certificate') or ''
    try:
        privileged.call_private('cloudflare', 'install_cert', domain=site, key_pem=key_pem, cert_pem=cert_pem)
    except RuntimeError as exc:
        service.audit(context, zone['id'], 'origin certificate (install failed)', site, source)
        return error('The certificate was created at Cloudflare but could not be installed: %s' % exc)
    service.audit(context, zone['id'], 'origin certificate', site, source)
    return ok(result={'site': site, 'hostnames': hostnames, 'expires_on': cert.get('expires_on'), 'id': cert.get('id')})


# --------------------------------------------------------------------------------------- audit

@api
def audit_log(request, data, context):
    return ok(result={'entries': service.audit_entries(None if context.is_admin else context.user_id)})
