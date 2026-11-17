"""Start-at-boot control on the Services page, and socket-activated units (Cockpit)."""
from unittest import TestCase

from serverStatus import views


class FakeSystemctl:
    """Answers the read-only systemctl queries the page makes; records everything else."""

    def __init__(self, files, active=None, enabled=None, fail=False):
        self.files, self.active, self.enabled, self.fail = files, active or {}, enabled or {}, fail
        self.calls = []

    def __call__(self, command, shell=False, retRequired=False):
        self.calls.append(command)
        if command.startswith('systemctl list-unit-files'):
            return '\n'.join('%s enabled' % f for f in self.files)
        if command.startswith('systemctl is-active'):
            return '\n'.join(self.active.get(u, 'inactive') for u in command.split()[2:])
        if command.startswith('systemctl is-enabled'):
            return '\n'.join(self.enabled.get(u, 'disabled') for u in command.split()[2:])
        return (0, 'failed') if self.fail else (1, '')


class ExtraServices(TestCase):

    def test_socket_unit_is_listed_with_boot_state_and_service_memory(self):
        fake = FakeSystemctl(['cockpit.socket', 'fail2ban.service', 'firewalld.service'],
                             active={'cockpit.socket': 'active', 'fail2ban': 'active'},
                             enabled={'cockpit.socket': 'enabled', 'fail2ban.service': 'enabled',
                                      'firewalld.service': 'enabled'})
        table = [(50 * 1048576, 'cockpit.service', 'cockpit-ws')]
        rows = {r['unit']: r for r in views.extra_services(table, executor=fake)}
        self.assertEqual(rows['cockpit.socket']['boot'], 'enabled')
        self.assertTrue(rows['cockpit.socket']['bootControl'])
        self.assertEqual(rows['cockpit.socket']['mem'], 50 * 1048576)
        self.assertFalse(rows['firewalld']['bootControl'])          # locked: keeps the server reachable


class SetAutostart(TestCase):

    def test_enable_extra_service_uses_unit_file_name(self):
        fake = FakeSystemctl([], enabled={'cockpit.socket': 'enabled'})
        reply = views.set_autostart('cockpit.socket', 'enable', executor=fake)
        self.assertEqual(reply['serviceAction'], 1)
        self.assertIn('sudo systemctl enable cockpit.socket', fake.calls)

    def test_core_key_resolves_to_installed_unit(self):
        fake = FakeSystemctl(['mariadb.service'], enabled={'mariadb.service': 'disabled'})
        reply = views.set_autostart('mysql', 'disable', executor=fake)
        self.assertEqual(reply['serviceAction'], 1)
        self.assertIn('sudo systemctl disable mariadb.service', fake.calls)

    def test_locked_and_unknown_services_refused(self):
        fake = FakeSystemctl(['lsws.service'])
        self.assertEqual(views.set_autostart('firewalld', 'disable', executor=fake)['serviceAction'], 0)
        self.assertEqual(views.set_autostart('lsws', 'disable', executor=fake)['serviceAction'], 0)
        self.assertEqual(views.set_autostart('sshd; reboot', 'disable', executor=fake)['serviceAction'], 0)
        self.assertFalse([c for c in fake.calls if c.startswith('sudo')])

    def test_failure_reported(self):
        fake = FakeSystemctl([], fail=True)
        self.assertEqual(views.set_autostart('fail2ban', 'enable', executor=fake)['serviceAction'], 0)
