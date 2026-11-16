"""Install, upgrade and High Availability status stay local: no network call by default."""
import ast
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class NoNetwork:
    """Fail the test on any outgoing HTTP request or socket connection."""

    def __enter__(self):
        import requests

        def refuse(*args, **kwargs):
            raise AssertionError('network call attempted: %r' % (args[:2],))
        self.patches = [patch.object(requests, 'post', side_effect=refuse),
                        patch.object(requests, 'get', side_effect=refuse),
                        patch.object(requests.Session, 'request', side_effect=refuse),
                        patch.object(urllib.request, 'urlopen', side_effect=refuse),
                        patch.object(socket.socket, 'connect', side_effect=refuse),
                        patch.object(socket, 'create_connection', side_effect=refuse)]
        self.mocks = [p.start() for p in self.patches]
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()
        return False

    def assert_quiet(self, case):
        for item in self.mocks:
            case.assertFalse(item.called, 'network call attempted')


class LocalStatusTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        from plogical import telemetryReceivers
        receivers = patch.object(telemetryReceivers, 'CONFIG_PATH', str(self.tmp / 'status-receivers.json'))
        receivers.start()
        self.addCleanup(receivers.stop)
        env = patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('INDIANSCLOUD_INSTALL_STATUS_URL', None)

    def test_install_log_writes_locally_only(self):
        from install.installLog import InstallLog
        self.assertEqual(InstallLog.LogURL, '')
        with patch.object(InstallLog, 'fileName', str(self.tmp / 'installLogs.txt')), NoNetwork() as guard:
            InstallLog.writeToFile('Installing packages,20')
        guard.assert_quiet(self)
        self.assertIn('Installing packages,20', (self.tmp / 'installLogs.txt').read_text())

    def test_upgrade_status_writes_locally_only(self):
        from plogical.CyberPanelUpgrade import UpgradeCyberPanel
        upgrade = object.__new__(UpgradeCyberPanel)
        upgrade.ipAddress = '192.0.2.10'
        with patch.object(UpgradeCyberPanel, 'LocalLog', str(self.tmp / 'upgrade.log')), NoNetwork() as guard:
            upgrade.PostStatus('Updating database..,45')
        guard.assert_quiet(self)
        text = (self.tmp / 'upgrade.log').read_text()
        self.assertIn('Updating database..,45', text)
        self.assertNotIn('192.0.2.10', text)

    def cluster(self):
        from plogical.ClusterManager import ClusterManager
        manager = object.__new__(ClusterManager)
        manager.config = {'name': 'qa-cluster', 'token': 'SYNTHETIC-CLOUD-TOKEN'}
        manager.type = 'Master'
        manager.ipAddress = '192.0.2.10'
        return ClusterManager, manager

    def test_ha_status_and_uptime_write_locally_only(self):
        ClusterManager, manager = self.cluster()
        with patch.object(ClusterManager, 'StatusLog', str(self.tmp / 'ha.log')), \
                patch.object(ClusterManager, 'UptimeFile', str(self.tmp / 'ha-uptime')), NoNetwork() as guard:
            manager.PostStatus('Master up. [200]')
            manager.PingNow()
            manager.Uptime()
        guard.assert_quiet(self)
        self.assertIn('Master up. [200]', (self.tmp / 'ha.log').read_text())
        self.assertTrue((self.tmp / 'ha-uptime').read_text().startswith('qa-cluster '))
        self.assertNotIn('SYNTHETIC-CLOUD-TOKEN', (self.tmp / 'ha.log').read_text())

    def test_configured_receiver_gets_status_without_cloud_token(self):
        config = self.tmp / 'status-receivers.json'
        config.write_text(json.dumps({'ha_uptime_url': 'https://monitor.example.test/ping/abc',
                                      'ha_status_url': 'http://insecure.example.test/'}))
        config.chmod(0o600)
        ClusterManager, manager = self.cluster()
        import requests
        with patch.object(ClusterManager, 'StatusLog', str(self.tmp / 'ha.log')), \
                patch.object(ClusterManager, 'UptimeFile', str(self.tmp / 'ha-uptime')), \
                patch.object(requests, 'post') as post:
            manager.PostStatus('ignored: http receiver is refused')
            post.assert_not_called()
            manager.Uptime()
        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], 'https://monitor.example.test/ping/abc')
        self.assertNotIn('SYNTHETIC-CLOUD-TOKEN', json.dumps(post.call_args.kwargs['json']))

    def test_install_receiver_only_when_set(self):
        import importlib
        import install.installLog as module
        os.environ['INDIANSCLOUD_INSTALL_STATUS_URL'] = 'https://receiver.example.test/install'
        try:
            importlib.reload(module)
            import requests
            with patch.object(module.InstallLog, 'fileName', str(self.tmp / 'i.txt')), patch.object(requests, 'post') as post:
                module.InstallLog.writeToFile('step,10')
            self.assertEqual(post.call_args.args[0], 'https://receiver.example.test/install')
        finally:
            os.environ.pop('INDIANSCLOUD_INSTALL_STATUS_URL', None)
            importlib.reload(module)
        self.assertEqual(module.InstallLog.LogURL, '')


class SourceTests(unittest.TestCase):
    def test_no_vendor_receivers_left(self):
        for relative in ('install/installLog.py', 'plogical/CyberPanelUpgrade.py', 'plogical/ClusterManager.py',
                         'plogical/telemetryReceivers.py'):
            tree = ast.parse((ROOT / relative).read_text())
            constants = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
            with self.subTest(file=relative):
                self.assertFalse([c for c in constants if c.startswith('http') and ('cyberpersons' in c or 'cyberpanel.net' in c)])

    def test_shell_installer_posts_only_to_configured_receiver(self):
        text = (ROOT / 'cyberpanel.sh').read_text()
        self.assertNotIn('servers/RecvData', text.replace('# (cloud.cyberpanel.net/servers/RecvData)', ''))
        self.assertIn('INDIANSCLOUD_INSTALL_STATUS_URL', text)


if __name__ == '__main__':
    unittest.main()
