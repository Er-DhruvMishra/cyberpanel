"""Pre-filter detections, secret redaction and model-output parse safety."""
import json
import os
import shutil
import tempfile
import time

from django.test import SimpleTestCase

from aiScanner import pipeline, prefilter


def hits_of(text, path='index.php', kind='php', mtime=None):
    return {h[0] for h in prefilter.scan_content(path, text, kind, mtime=mtime)}


class PrefilterDetectionTests(SimpleTestCase):
    def test_php_backdoors(self):
        self.assertIn('php_eval_decode', hits_of('<?php @eval(base64_decode("ZWNobyAxOw=="));'))
        self.assertIn('php_eval_decode', hits_of('<?php eval ( gzinflate(base64_decode($x)));'))
        self.assertIn('php_decode_chain', hits_of('<?php $a = gzinflate(base64_decode($p));'))
        self.assertIn('php_eval_input', hits_of('<?php eval($_POST["c"]);'))
        self.assertIn('php_exec_input', hits_of('<?php system($_GET["cmd"]);'))
        self.assertIn('php_dynamic_call_input', hits_of('<?php $_REQUEST["f"]($_REQUEST["a"]);'))
        self.assertIn('php_preg_e', hits_of("<?php preg_replace('/.*/e', $_POST['x'], '');"))
        self.assertIn('php_write_input', hits_of('<?php file_put_contents("x.php", $_POST["d"]);'))
        self.assertIn('php_long_base64', hits_of('<?php $p = "%s";' % ('QUJD' * 150)))
        self.assertIn('php_hex_escapes', hits_of('<?php $f = "%s";' % ('\\x41' * 30)))
        self.assertIn('php_chr_chain', hits_of('<?php $f = %s"";' % ('chr(101).' * 10)))
        self.assertIn('webshell_marker', hits_of('<?php // FilesMan\n'))
        self.assertIn('php_long_line', hits_of('<?php $a=1;' + 'b' * 6000))

    def test_location_heuristics(self):
        now = time.time()
        found = prefilter.scan_content('wp-content/uploads/2026/11/x.php', '<?php echo 1;', 'php', mtime=now - 3600, now=now)
        names = {h[0]: h for h in found}
        self.assertIn('php_in_uploads', names)
        self.assertIn('last 7 days', names['php_in_uploads'][3])
        self.assertIn('shell_filename', hits_of('<?php echo 1;', path='wp-includes/wso.php'))
        self.assertIn('hidden_php', hits_of('<?php echo 1;', path='images/.cache.php'))

    def test_js_html_htaccess_and_images(self):
        self.assertIn('js_eval_decode', hits_of('eval(atob("YWxlcnQoMSk="))', 'a.js', 'js'))
        self.assertIn('js_function_atob', hits_of('new Function(atob(x))()', 'a.js', 'js'))
        self.assertIn('js_document_write_unescape', hits_of('document.write(unescape("%3Cscript"))', 'a.js', 'js'))
        self.assertIn('htaccess_prepend', hits_of('php_value auto_prepend_file /tmp/x.php', '.htaccess', 'htaccess'))
        self.assertIn('htaccess_image_handler', hits_of('AddHandler application/x-httpd-php .jpg', '.htaccess', 'htaccess'))
        self.assertIn('php_in_image', hits_of('GIF89a<?php system($_GET[1]); ?>', 'logo.gif', 'image'))
        self.assertIn('html_hidden_script_php', hits_of('<html><?php echo 1; ?>', 'a.html', 'html'))

    def test_clean_code_has_no_hits(self):
        clean = '<?php\nfunction hello($name) { return "Hello " . htmlspecialchars($name); }\necho hello("x");\n'
        self.assertEqual(prefilter.scan_content('wp-content/plugins/a/a.php', clean, 'php'), [])
        self.assertEqual(prefilter.scan_content('a.js', 'function f(a){return a+1}', 'js'), [])

    def test_line_numbers(self):
        text = '<?php\n// one\n// two\neval(base64_decode($x));\n'
        hit = [h for h in prefilter.scan_content('a.php', text, 'php') if h[0] == 'php_eval_decode'][0]
        self.assertEqual(hit[2], 4)


class RedactionTests(SimpleTestCase):
    def test_wordpress_secrets(self):
        src = ("define('DB_NAME', 'shop');\ndefine( 'DB_PASSWORD', 'p@ss\\'word' );\n"
               "define('AUTH_KEY', 'k3y!');\ndefine('NONCE_SALT', 'salt$$');\ndefine('WP_DEBUG', false);\n")
        out, count = prefilter.redact(src)
        for secret in ('shop', "p@ss", 'k3y!', 'salt$$'):
            self.assertNotIn(secret, out)
        self.assertIn("define('WP_DEBUG', false)", out)
        self.assertGreaterEqual(count, 4)
        self.assertEqual(out.count('\n'), src.count('\n'))

    def test_variables_arrays_env_and_tokens(self):
        src = '\n'.join([
            '$db_password = "hunter2";',
            "$config = ['api_key' => 'abc123', 'title' => 'Shop'];",
            'DB_PASSWORD=supersecret',
            'export STRIPE_SECRET=sk_live_abcdefghijklmnop',
            '$k = "AKIAABCDEFGHIJKLMNOP";',
            '$g = "AIza' + 'A' * 35 + '";',
            '$o = "sk-proj-abcdefghijklmnopqrstuv";',
            '$a = "sk-ant-api03-abcdefghijklmnopqrstuvwx";',
            '$gh = "ghp_' + 'a' * 36 + '";',
            '$j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";',
            '$u = "mysql://root:toor@db/shop";',
            '$m = mysqli_connect("localhost", "root", "rootpw");',
            '$mail = "owner@example.com";',
            'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
            '-----BEGIN RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEA', '-----END RSA PRIVATE KEY-----',
        ])
        out, _ = prefilter.redact(src)
        for secret in ('hunter2', 'abc123', 'supersecret', 'sk_live_abcdefghijklmnop', 'AKIAABCDEFGHIJKLMNOP', 'AIza',
                       'sk-proj-', 'sk-ant-', 'ghp_', 'eyJhbGci', 'toor', 'rootpw', 'owner@example.com',
                       'abcdefghijklmnopqrstuvwxyz123456', 'MIIEowIBAAKCAQEA'):
            self.assertNotIn(secret, out, secret)
        self.assertIn("'title' => 'Shop'", out)
        self.assertEqual(out.count('\n'), src.count('\n'))

    def test_config_files_send_structure_only(self):
        src = "<?php\ndefine('DB_HOST', 'db.internal');\n$table_prefix = 'wp_';\n@eval(base64_decode('ZXZpbA=='));\n"
        structure = prefilter.config_structure(src)
        self.assertNotIn('db.internal', structure)
        self.assertNotIn('wp_', structure)
        self.assertNotIn('ZXZpbA', structure)
        self.assertIn('eval(base64_decode(', structure)
        self.assertTrue(prefilter.is_config_file('wp-config.php'))
        self.assertTrue(prefilter.is_config_file('.env.production'))
        self.assertFalse(prefilter.is_config_file('index.php'))

    def test_snippet_redacts_and_limits(self):
        text = "<?php\n$pass = 'topsecret';\n" + '\n'.join('// filler %d' % i for i in range(500)) + '\neval(base64_decode($x));\n'
        hits = prefilter.scan_content('a.php', text, 'php')
        snippet, _ = prefilter.build_snippet(text, hits)
        self.assertNotIn('topsecret', snippet)
        self.assertIn('eval(base64_decode', snippet)
        self.assertLessEqual(len(snippet), prefilter.SNIPPET_MAX_CHARS + 40)
        long_blob = "<?php eval(base64_decode('%s'));" % ('A' * 5000)
        snippet, _ = prefilter.build_snippet(long_blob, prefilter.scan_content('b.php', long_blob, 'php'))
        self.assertLess(len(snippet), 1000)


class TreeWalkTests(SimpleTestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.root = os.path.join(self.base, 'public_html')
        self.outside = os.path.join(self.base, 'private')
        os.makedirs(os.path.join(self.root, 'wp-content', 'uploads'))
        os.makedirs(self.outside)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def write(self, rel, text, base=None):
        path = os.path.join(base or self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as handle:
            handle.write(text)
        return path

    def test_walk_finds_candidates_and_never_leaves_root(self):
        self.write('index.php', '<?php echo "hi";')
        self.write('wp-content/uploads/x.php', '<?php @eval(base64_decode($_POST["a"]));')
        self.write('wp-config.php', "<?php define('DB_PASSWORD', 'hunter2'); eval(base64_decode('x'));")
        secret = self.write('evil.php', '<?php eval(base64_decode($x)); // OUTSIDE-SECRET', base=self.outside)
        os.symlink(secret, os.path.join(self.root, 'link.php'))
        os.symlink(self.outside, os.path.join(self.root, 'linkdir'))
        report = prefilter.scan_tree(self.root)
        paths = {c['path']: c for c in report['candidates']}
        self.assertIn('wp-content/uploads/x.php', paths)
        self.assertIn('wp-config.php', paths)
        self.assertNotIn('index.php', paths)
        self.assertNotIn('link.php', paths)
        self.assertFalse(any(p.startswith('linkdir') for p in paths))
        self.assertNotIn('OUTSIDE-SECRET', json.dumps(report))
        self.assertGreaterEqual(report['skipped']['symlinks'], 2)
        self.assertTrue(paths['wp-config.php']['config'])
        self.assertNotIn('hunter2', paths['wp-config.php']['snippet'])
        self.assertEqual(paths['wp-content/uploads/x.php']['severity'], 'critical')

    def test_hardlinked_file_is_not_sent(self):
        target = self.write('real.php', '<?php eval($_POST["x"]);', base=self.outside)
        os.link(target, os.path.join(self.root, 'hl.php'))
        report = prefilter.scan_tree(self.root)
        cand = [c for c in report['candidates'] if c['path'] == 'hl.php'][0]
        self.assertFalse(cand['send_ai'])
        self.assertEqual(cand['snippet'], '')

    def test_symlinked_root_is_refused(self):
        link = os.path.join(self.base, 'rootlink')
        os.symlink(self.root, link)
        self.assertIn('error', prefilter.scan_tree(link))

    def test_main_prints_marked_json(self):
        self.write('a.php', '<?php system($_GET["c"]);')
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            prefilter.main(['--root', self.root])
        line = buf.getvalue().strip()
        self.assertTrue(line.startswith('AISCANNER-JSON:'))
        report = pipeline.run_prefilter(self.root, 'site1', runner=lambda cmd, user: 'noise\n' + line + '\n')
        self.assertEqual(report['candidates'][0]['path'], 'a.php')

    def test_prefilter_command_runs_as_site_user(self):
        seen = {}

        def runner(command, user):
            seen['command'], seen['user'] = command, user
            return 'AISCANNER-JSON:' + json.dumps(prefilter.scan_tree(self.root))
        pipeline.run_prefilter("/home/ex'ample.com/public_html", 'exam1234', runner=runner)
        self.assertEqual(seen['user'], 'exam1234')
        self.assertIn(" -I ", seen['command'])
        self.assertIn("'/home/ex'\"'\"'ample.com/public_html'", seen['command'])
        with self.assertRaises(pipeline.ScanError):
            pipeline.run_prefilter(self.root, 'root; rm -rf /', runner=runner)


class ParseSafetyTests(SimpleTestCase):
    IDS = ['F1', 'F2']

    def test_valid_answer(self):
        text = json.dumps({'files': [{'id': 'F1', 'verdict': 'malicious', 'severity': 'critical',
                                      'findings': [{'line': 3, 'reason': 'backdoor', 'action': 'delete'}]}]})
        out = pipeline.parse_ai_output(text, self.IDS)
        self.assertEqual(out['F1']['findings'][0], {'line': 3, 'reason': 'backdoor', 'action': 'delete'})

    def test_fences_and_prose_are_tolerated(self):
        text = 'Sure! ```json\n{"files":[{"id":"F2","verdict":"clean","severity":"info","findings":[]}]}\n```'
        self.assertEqual(pipeline.parse_ai_output(text, self.IDS)['F2']['verdict'], 'clean')
        text = 'Here you go: {"files":[{"id":"F2","verdict":"clean","severity":"info","findings":[]}]} thanks'
        self.assertEqual(pipeline.parse_ai_output(text, self.IDS)['F2']['verdict'], 'clean')

    def test_garbage_and_hostile_values(self):
        for text in ('', 'not json', '[1,2,3]', '{"files": "x"}', '{"files":[null, 5, "F1"]}', 'x' * 300000,
                     '{' * 5000):
            self.assertEqual(pipeline.parse_ai_output(text, self.IDS), {})
        text = json.dumps({'files': [
            {'id': 'F9', 'verdict': 'clean'},                               # unknown id
            {'id': 'F1', 'verdict': 'pwned', 'severity': 'apocalyptic',     # bad enums
             'findings': [{'line': '7', 'reason': '<img src=x onerror=alert(1)>\x00‮', 'action': 'a' * 999},
                          {'line': -4, 'reason': 'neg'}, {'line': True, 'reason': 'bool'}, {'reason': ''}, 'str']},
            {'id': 'F1', 'verdict': 'clean'},                               # duplicate id ignored
        ]})
        out = pipeline.parse_ai_output(text, self.IDS)
        self.assertEqual(set(out), {'F1'})
        self.assertEqual(out['F1']['verdict'], 'suspicious')
        self.assertEqual(out['F1']['severity'], 'medium')
        first = out['F1']['findings'][0]
        self.assertEqual(first['line'], 7)
        self.assertNotIn('\x00', first['reason'])
        self.assertNotIn('‮', first['reason'])
        self.assertEqual(first['reason'], '<img src=x onerror=alert(1)>')  # kept as plain text, rendered via textContent
        self.assertEqual(len(first['action']), 200)
        self.assertIsNone(out['F1']['findings'][1]['line'])
        self.assertIsNone(out['F1']['findings'][2]['line'])
        self.assertEqual(len(out['F1']['findings']), 3)

    def test_ai_cannot_erase_local_critical_findings(self):
        candidate = {'path': 'a.php', 'hits': [
            {'rule': 'webshell_marker', 'severity': 'critical', 'line': 1, 'reason': 'shell', 'action': 'delete'},
            {'rule': 'php_long_base64', 'severity': 'medium', 'line': 2, 'reason': 'blob', 'action': 'review'}]}
        findings = pipeline.merge_findings([candidate], {'a.php': {'verdict': 'clean', 'severity': 'info', 'findings': []}})
        by_rule = {f['rule']: f for f in findings}
        self.assertEqual(by_rule['webshell_marker']['severity'], 'critical')
        self.assertIn('verify manually', by_rule['webshell_marker']['reason'])
        self.assertEqual(by_rule['php_long_base64']['severity'], 'low')
        findings = pipeline.merge_findings([candidate], {'a.php': {'verdict': 'malicious', 'severity': 'high',
                                                                   'findings': [{'line': 9, 'reason': 'r', 'action': ''}]}})
        ai = [f for f in findings if f['source'] == 'ai'][0]
        self.assertEqual((ai['file'], ai['line'], ai['severity']), ('a.php', 9, 'high'))
        self.assertEqual(set(findings[0]), {'severity', 'file', 'line', 'reason', 'action', 'source', 'rule', 'ai_verdict'})

    def test_template_renders_findings_as_text_only(self):
        path = os.path.join(os.path.dirname(pipeline.__file__), 'templates', 'aiScanner', 'scanner.html')
        with open(path) as handle:
            source = handle.read()
        self.assertNotIn('innerHTML', source)
        self.assertNotIn('insertAdjacentHTML', source)
        self.assertNotIn('eval(', source)
