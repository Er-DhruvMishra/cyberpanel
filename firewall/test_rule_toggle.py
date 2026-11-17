"""Firewall rule enable/disable, live status, lock-out protection and bulk actions.

firewall-cmd is never run: ProcessUtilities.executioner / outputExecutioner are mocked and
record the commands they were given.
"""
import json
import os
from types import SimpleNamespace
from unittest import mock

from django.db import connection
from django.test import RequestFactory, TestCase

from firewall import ruleToggle, views
from firewall.firewallManager import FirewallManager
from firewall.models import FirewallRules
from plogical.firewallUtilities import FirewallUtilities
from universalAddons.models import FirewallRuleState

LIVE_RICH = '''rule family="ipv6" port port="53" protocol="tcp" accept
rule family="ipv4" source address="0.0.0.0/0" port port="8090" protocol="tcp" accept
rule family="ipv6" port port="8090" protocol="tcp" accept
rule family="ipv4" source address="0.0.0.0/0" port port="80" protocol="tcp" accept
rule family="ipv6" port port="80" protocol="tcp" accept
rule family="ipv4" source address="0.0.0.0/0" port port="40110-40210" protocol="tcp" accept
rule family="ipv4" source address="192.187.115.90" drop
rule family="ipv4" source address="93.123.16.156" port port="ssh" protocol="tcp" reject type="icmp-port-unreachable"
rule family="ipv4" source address="10.0.0.5" port port="3306" protocol="tcp" accept
rule family="ipv6" port port="3306" protocol="tcp" accept
rule family="ipv4" source address="0.0.0.0/0" port port="9999" protocol="tcp" log prefix="x" accept
rule family="ipv4" source NOT address="1.2.3.4" port port="7777" protocol="tcp" accept
rule family="ipv4 source address="broken
'''
LIVE_PORTS = '3478/tcp 4190/tcp 5349/tcp 3478/udp 49152-65535/udp\n'
SSHD = 'Port 22\n#Port 2200\nPort 2222\nPermitRootLogin yes\n'


class FakeRoot:
    """Stands in for lscpd: records commands, answers the two read-only list commands."""

    def __init__(self, rich=LIVE_RICH, ports=LIVE_PORTS, ok=1, firewalld_running=True):
        self.commands = []
        self.rich, self.ports, self.ok, self.running = rich, ports, ok, firewalld_running

    def executioner(self, command, user=None, shell=False):
        self.commands.append(command)
        return self.ok

    def outputExecutioner(self, command, user=None, shell=None, dir=None, retRequired=None):
        self.commands.append(command)
        if not self.running:
            return (0, 'FirewallD is not running\n') if retRequired else 'FirewallD is not running\n'
        if 'list-rich-rules' in command:
            out = self.rich
        elif 'list-ports' in command:
            out = self.ports
        else:
            out = ''
        return (1, out) if retRequired else out

    def changes(self):
        return [c for c in self.commands if '--list-' not in c]

    def reloads(self):
        return [c for c in self.commands if c == 'firewall-cmd --reload']


def files(path):
    return {ruleToggle.SSHD_CONFIG: SSHD, ruleToggle.PANEL_PORT_FILE: '*:8090\n'}.get(path)


class RuleWorld(TestCase):
    """FirewallRules has no migration files, so its table is created here for the test run."""

    @classmethod
    def setUpClass(cls):
        cls._created = FirewallRules._meta.db_table not in connection.introspection.table_names()
        if cls._created:
            with connection.schema_editor() as editor:
                editor.create_model(FirewallRules)
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        if cls._created:
            with connection.schema_editor() as editor:
                editor.delete_model(FirewallRules)

    def setUp(self):
        self.root = FakeRoot()
        patches = [
            mock.patch('plogical.processUtilities.ProcessUtilities.executioner', side_effect=self.root.executioner),
            mock.patch('plogical.processUtilities.ProcessUtilities.outputExecutioner',
                       side_effect=self.root.outputExecutioner),
            mock.patch('firewall.ruleToggle._read_text', side_effect=files),
            mock.patch('firewall.firewallManager.ACLManager.loadedACL', return_value={'admin': 1}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.panel = FirewallRules.objects.create(name='panel', proto='tcp', port='8090', ipAddress='0.0.0.0/0')
        self.http = FirewallRules.objects.create(name='http', proto='tcp', port='80', ipAddress='0.0.0.0/0')
        self.mysql = FirewallRules.objects.create(name='mysql', proto='tcp', port='3306', ipAddress='10.0.0.5')
        self.dns = FirewallRules.objects.create(name='dns', proto='udp', port='53', ipAddress='0.0.0.0/0')
        self.ftp = FirewallRules.objects.create(name='ftptls', proto='tcp', port='40110-40210', ipAddress='0.0.0.0/0')

    def call(self, method, data, admin=1):
        with mock.patch('firewall.firewallManager.ACLManager.loadedACL', return_value={'admin': admin}):
            response = getattr(FirewallManager(), method)(1, data)
        return json.loads(response.content)

    def state(self, rule):
        return FirewallRuleState.objects.filter(rule_id=rule.id).first()


class DisableEnable(RuleWorld):

    def test_disable_removes_both_families_and_keeps_the_row(self):
        body = self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        self.assertEqual(body['state_status'], 1, body)
        self.assertEqual(self.root.changes(), [
            "firewall-cmd --permanent --zone=public --remove-rich-rule='rule family=\"ipv4\" source address=\"0.0.0.0/0\" port protocol=\"tcp\" port=\"80\" accept'",
            "firewall-cmd --permanent --zone=public --remove-rich-rule='rule family=\"ipv6\"  port protocol=\"tcp\" port=\"80\" accept'",
            'firewall-cmd --reload',
        ])
        self.assertTrue(FirewallRules.objects.filter(id=self.http.id).exists())
        st = self.state(self.http)
        self.assertFalse(st.enabled)
        self.assertIsNotNone(st.disabled_at)

    def test_enable_readds_exactly_what_add_rule_applies(self):
        self.call('setRulesState', {'ids': [self.mysql.id], 'action': 'disable'})
        self.root.commands.clear()
        body = self.call('setRulesState', {'ids': [self.mysql.id], 'action': 'enable'})
        self.assertEqual(body['state_status'], 1, body)
        enabled = self.root.changes()

        self.root.commands.clear()
        FirewallUtilities.addRule('tcp', '3306', '10.0.0.5')
        self.assertEqual(enabled, self.root.changes())
        self.assertEqual(len(enabled), 3)
        self.assertIn('source address="10.0.0.5"', enabled[0])
        st = self.state(self.mysql)
        self.assertTrue(st.enabled)
        self.assertIsNone(st.disabled_at)

    def test_enable_of_enabled_and_disable_of_disabled_change_nothing(self):
        body = self.call('setRulesState', {'ids': [self.http.id], 'action': 'enable'})
        self.assertEqual(body['state_status'], 1)
        self.assertEqual(self.root.changes(), [])
        self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        self.root.commands.clear()
        self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        self.assertEqual(self.root.changes(), [])

    def test_failed_firewall_cmd_does_not_mark_disabled(self):
        self.root.ok = 0
        body = self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        self.assertEqual(body['state_status'], 0)
        self.assertIsNone(self.state(self.http))

    def test_reapply_readds_an_enabled_rule_and_refuses_a_disabled_one(self):
        body = self.call('setRulesState', {'ids': [self.dns.id], 'action': 'reapply'})
        self.assertEqual(body['state_status'], 1)
        self.assertEqual(len([c for c in self.root.changes() if '--add-rich-rule' in c]), 2)
        self.call('setRulesState', {'ids': [self.dns.id], 'action': 'disable'})
        self.root.commands.clear()
        body = self.call('setRulesState', {'ids': [self.dns.id], 'action': 'reapply'})
        self.assertEqual(body['state_status'], 0)
        self.assertEqual(self.root.changes(), [])


class LiveStatus(RuleWorld):

    def test_parser_reads_panel_shaped_rules_only(self):
        found = ruleToggle.parse_rich_rules(LIVE_RICH)
        self.assertIn(('ipv4', '0.0.0.0/0', '8090', 'tcp'), found)
        self.assertIn(('ipv6', None, '8090', 'tcp'), found)
        self.assertIn(('ipv4', '10.0.0.5/32', '3306', 'tcp'), found)
        self.assertIn(('ipv4', '0.0.0.0/0', '40110-40210', 'tcp'), found)
        # drop / reject / service port / log / NOT / broken quoting are not port-allow rules
        self.assertEqual(len(found), 8)
        for port in ('ssh', '9999', '7777'):
            self.assertFalse([k for k in found if k[2] == port])
        self.assertIsNone(ruleToggle.parse_rich_rule('rule family="ipv4" source address="x" port port="1" protocol="tcp" accept'))
        self.assertIsNone(ruleToggle.parse_rich_rule('; rm -rf /'))
        self.assertEqual(ruleToggle.parse_ports(LIVE_PORTS),
                         {('3478', 'tcp'), ('4190', 'tcp'), ('5349', 'tcp'), ('3478', 'udp'), ('49152-65535', 'udp')})

    def test_statuses(self):
        rows, live, protected = ruleToggle.describe_rules(FirewallRules.objects.order_by('id'))
        by = {r['name']: r for r in rows}
        self.assertTrue(live)
        self.assertEqual(by['panel']['status'], 'active')
        self.assertEqual(by['http']['status'], 'active')
        self.assertEqual(by['mysql']['status'], 'active')
        # dns/udp/53 has neither family in firewalld
        self.assertEqual(by['dns']['status'], 'missing')
        self.assertEqual(by['dns']['missingFamilies'], ['ipv4', 'ipv6'])
        # ftptls has IPv4 only
        self.assertEqual(by['ftptls']['status'], 'missing')
        self.assertEqual(by['ftptls']['missingFamilies'], ['ipv6'])
        # one read of each list per listing
        self.assertEqual(len([c for c in self.root.commands if 'list-rich-rules' in c]), 1)
        self.assertEqual(len([c for c in self.root.commands if 'list-ports' in c]), 1)

    def test_port_list_counts_as_open_and_disabled_shows_disabled(self):
        sieve = FirewallRules.objects.create(name='sieve', proto='tcp', port='4190', ipAddress='0.0.0.0/0')
        live = ruleToggle.read_live_state()
        self.assertEqual(ruleToggle.live_status(sieve, True, live)[0], 'active')
        status, details = ruleToggle.live_status(self.http, False, live)
        self.assertEqual(status, 'disabled')
        self.assertIn('still allows', details['note'])

    def test_firewalld_not_running_gives_unknown(self):
        self.root.running = False
        rows, live, _ = ruleToggle.describe_rules(FirewallRules.objects.all())
        self.assertFalse(live)
        self.assertEqual({r['status'] for r in rows}, {'unknown'})

    def test_get_current_rules_payload(self):
        self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        body = json.loads(FirewallManager().getCurrentRules(1).content)
        self.assertEqual(body['fetchStatus'], 1)
        self.assertEqual(body['liveState'], 1)
        rows = {r['name']: r for r in json.loads(body['data'])}
        self.assertEqual(rows['http']['enabled'], 0)
        self.assertEqual(rows['http']['status'], 'disabled')
        self.assertTrue(rows['http']['disabledAt'])
        self.assertEqual(rows['panel']['protected'], 'panel')
        self.assertEqual(rows['http']['protected'], '')
        self.assertEqual(body['protectedPorts'], {'22': 'SSH', '2222': 'SSH', '8090': 'panel'})


class Lockout(RuleWorld):

    def test_protected_ports_and_rule_matching(self):
        protected = ruleToggle.protected_ports()
        self.assertEqual(protected, {22: 'SSH', 2222: 'SSH', 8090: 'panel'})
        mk = lambda proto, port: SimpleNamespace(proto=proto, port=port)
        self.assertEqual(ruleToggle.rule_protection(mk('tcp', '8090'), protected), 'panel')
        self.assertEqual(ruleToggle.rule_protection(mk('tcp', '2222'), protected), 'SSH')
        self.assertEqual(ruleToggle.rule_protection(mk('tcp', '20-25'), protected), 'SSH')
        self.assertEqual(ruleToggle.rule_protection(mk('udp', '22'), protected), '')
        self.assertEqual(ruleToggle.rule_protection(mk('tcp', '80'), protected), '')

    def test_configured_panel_port_is_protected(self):
        with mock.patch('firewall.ruleToggle._read_text',
                        side_effect=lambda p: '*:7443\n' if p == ruleToggle.PANEL_PORT_FILE else None):
            self.assertEqual(ruleToggle.panel_ports(), {8090, 7443})

    def test_disable_of_panel_rule_needs_second_confirmation(self):
        body = self.call('setRulesState', {'ids': [self.panel.id], 'action': 'disable'})
        self.assertEqual(body['state_status'], 0)
        self.assertEqual([c['id'] for c in body['needsConfirm']], [self.panel.id])
        self.assertIn('IndiansCloud', body['error_message'])
        self.assertEqual(self.root.changes(), [])
        self.assertIsNone(self.state(self.panel))
        # a truthy non-boolean is not a confirmation
        body = self.call('setRulesState', {'ids': [self.panel.id], 'action': 'disable', 'confirmLockout': 'yes'})
        self.assertIn('needsConfirm', body)

        body = self.call('setRulesState', {'ids': [self.panel.id], 'action': 'disable', 'confirmLockout': True})
        self.assertEqual(body['state_status'], 1)
        self.assertFalse(self.state(self.panel).enabled)

    def test_bulk_with_a_protected_rule_changes_nothing_until_confirmed(self):
        body = self.call('setRulesState', {'ids': [self.http.id, self.panel.id], 'action': 'disable'})
        self.assertIn('needsConfirm', body)
        self.assertEqual(self.root.changes(), [])
        self.assertIsNone(self.state(self.http))

    def test_delete_of_protected_rule_needs_second_confirmation(self):
        body = self.call('deleteRule', {'id': self.panel.id})
        self.assertEqual(body['delete_status'], 0)
        self.assertIn('needsConfirm', body)
        self.assertTrue(FirewallRules.objects.filter(id=self.panel.id).exists())
        self.assertEqual(self.root.changes(), [])
        body = self.call('deleteRule', {'id': self.panel.id, 'confirmLockout': True})
        self.assertEqual(body['delete_status'], 1)
        self.assertFalse(FirewallRules.objects.filter(id=self.panel.id).exists())

    def test_enable_is_never_blocked(self):
        self.call('setRulesState', {'ids': [self.panel.id], 'action': 'disable', 'confirmLockout': True})
        body = self.call('setRulesState', {'ids': [self.panel.id], 'action': 'enable'})
        self.assertEqual(body['state_status'], 1)


class Delete(RuleWorld):

    def test_delete_uses_stored_values_not_client_values(self):
        body = self.call('deleteRule', {'id': self.http.id, 'proto': 'udp', 'port': '22', 'ruleIP': '1.1.1.1'})
        self.assertEqual(body['delete_status'], 1, body)
        changes = self.root.changes()
        self.assertEqual(len(changes), 3)
        self.assertTrue(all('port="80"' in c and 'protocol="tcp"' in c for c in changes[:2]))
        self.assertFalse(FirewallRules.objects.filter(id=self.http.id).exists())

    def test_delete_of_disabled_rule_skips_firewalld_and_forgets_state(self):
        self.call('setRulesState', {'ids': [self.http.id], 'action': 'disable'})
        self.root.commands.clear()
        body = self.call('deleteRule', {'id': self.http.id})
        self.assertEqual(body['delete_status'], 1)
        self.assertEqual(self.root.changes(), [])
        self.assertFalse(FirewallRuleState.objects.filter(rule_id=self.http.id).exists())

    def test_delete_unknown_id(self):
        body = self.call('deleteRule', {'id': 999999})
        self.assertEqual(body['delete_status'], 0)
        self.assertEqual(self.root.changes(), [])


class Bulk(RuleWorld):

    def test_bulk_disable_then_enable_reloads_once_each(self):
        ids = [self.http.id, self.mysql.id, self.dns.id]
        body = self.call('setRulesState', {'ids': ids, 'action': 'disable'})
        self.assertEqual(body['state_status'], 1, body)
        changes = self.root.changes()
        self.assertEqual(len([c for c in changes if '--remove-rich-rule' in c]), 6)
        self.assertEqual(len(self.root.reloads()), 1)
        self.assertEqual(changes[-1], 'firewall-cmd --reload')
        self.assertEqual(FirewallRuleState.objects.filter(rule_id__in=ids, enabled=False).count(), 3)
        self.assertEqual(FirewallRules.objects.filter(id__in=ids).count(), 3)

        self.root.commands.clear()
        body = self.call('setRulesState', {'ids': ids, 'action': 'enable'})
        self.assertEqual(body['state_status'], 1)
        self.assertEqual(len([c for c in self.root.changes() if '--add-rich-rule' in c]), 6)
        self.assertEqual(len(self.root.reloads()), 1)

    def test_bad_ids_and_actions_are_refused_before_any_change(self):
        for data in ({'ids': [True], 'action': 'disable'},
                     {'ids': ['1; rm -rf /'], 'action': 'disable'},
                     {'ids': [self.http.id, 999999], 'action': 'disable'},
                     {'ids': [], 'action': 'disable'},
                     {'ids': 'all', 'action': 'disable'},
                     {'ids': [-1], 'action': 'disable'},
                     {'ids': [1.5], 'action': 'disable'},
                     {'ids': list(range(1, 600)), 'action': 'disable'},
                     {'ids': [self.http.id], 'action': 'drop'},
                     ['not', 'a', 'dict']):
            body = self.call('setRulesState', data)
            self.assertEqual(body['state_status'], 0, data)
        self.assertEqual(self.root.changes(), [])
        self.assertEqual(FirewallRuleState.objects.count(), 0)

    def test_string_ids_are_accepted(self):
        body = self.call('setRulesState', {'ids': [str(self.http.id)], 'action': 'disable'})
        self.assertEqual(body['state_status'], 1)


class Access(RuleWorld):

    def test_non_admin_is_refused(self):
        for method, data in (('setRulesState', {'ids': [self.http.id], 'action': 'disable'}),
                             ('deleteRule', {'id': self.http.id}),
                             ('getCurrentRules', None)):
            with mock.patch('firewall.firewallManager.ACLManager.loadedACL', return_value={'admin': 0}):
                fm = FirewallManager()
                response = fm.getCurrentRules(1) if method == 'getCurrentRules' else getattr(fm, method)(1, data)
            body = json.loads(response.content)
            self.assertEqual(body['status'], 0, method)
            self.assertIn('not authorized', body['error_message'])
        self.assertEqual(self.root.commands, [])
        self.assertTrue(FirewallRules.objects.filter(id=self.http.id).exists())
        self.assertEqual(FirewallRuleState.objects.count(), 0)

    def test_view_requires_login_and_post(self):
        rf = RequestFactory()
        request = rf.post('/firewall/setRulesState', data='{}', content_type='application/json')
        request.session = {}
        response = views.setRulesState(request)
        self.assertEqual(response.status_code, 302)

        request = rf.get('/firewall/setRulesState')
        request.session = {'userID': 1}
        self.assertEqual(json.loads(views.setRulesState(request).content)['status'], 0)

        request = rf.post('/firewall/setRulesState', data='not json', content_type='application/json')
        request.session = {'userID': 1}
        self.assertEqual(json.loads(views.setRulesState(request).content)['status'], 0)
        self.assertEqual(self.root.changes(), [])

    def test_url_is_registered(self):
        from django.urls import resolve
        self.assertEqual(resolve('/firewall/setRulesState').func, views.setRulesState)


class Page(TestCase):

    def test_template_has_the_controls_and_a_fresh_cache_buster(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'firewall', 'templates', 'firewall', 'firewall.html'), encoding='utf-8') as f:
            html = f.read()
        self.assertIn("{% static 'firewall/firewall.js' %}?v={{ CP_VERSION }}-rules-20261117", html)
        for needle in ('toggleRule(rule)', 'reapplyRule(rule)', 'bulkSetState(\'disable\')', 'fa-lock',
                       "filterState == 'disabled'", 'ruleSearch', 'IndiansCloud'):
            self.assertIn(needle, html)
        with open(os.path.join(root, 'firewall', 'static', 'firewall', 'firewall.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn('Disable', js)
        self.assertIn('"/firewall/setRulesState"', js)
        self.assertIn('use "Disable" instead', js)
