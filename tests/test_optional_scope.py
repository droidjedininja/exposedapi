import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposedapi.cli import main
from exposedapi.scanner import HttpResponse, validate_target


class OptionalScopeTests(unittest.TestCase):
    def test_omitted_scope_preserves_other_url_checks(self):
        self.assertEqual(validate_target('https://any.example/item', None), 'any.example')
        for scope in ([], ['other.example']):
            with self.assertRaises(ValueError):
                validate_target('https://any.example/item', scope)
        for url, options in (
            ('file:///etc/passwd', {}),
            ('https://user:secret@any.example/item', {}),
            ('http://any.example/item', {'require_https': True}),
            ('https://any.example/item?token=secret', {'reject_sensitive_query': True}),
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_target(url, None, **options)

    def test_all_commands_without_scope_and_with_explicit_filters(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'MATRIX_AUTH': 'Bearer test'}):
            root = Path(directory)
            targets, har, matrix, scope = [root / name for name in ('targets', 'capture.har', 'matrix.json', 'scope')]
            targets.write_text('https://any.example/item\n')
            har.write_text(json.dumps({'log': {'entries': [{'request': {
                'method': 'GET', 'url': 'https://any.example/item',
                'headers': [{'name': 'Cookie', 'value': 'session=test'}]}}]}}))
            matrix.write_text(json.dumps({'accounts': {'owner': {'headers_env': {'Authorization': 'MATRIX_AUTH'}}},
                                         'resources': [{'url': 'https://any.example/item', 'allowed_accounts': ['owner']}]}))
            commands = [
                ['--targets', str(targets), '--acknowledge-authorization'],
                ['import-har', '--har', str(har)],
                ['compare-har', '--har-a', str(har), '--har-b', str(har), '--acknowledge-authorization'],
                ['account-matrix', '--matrix', str(matrix), '--acknowledge-authorization'],
            ]
            for index, command in enumerate(commands):
                for mode in ('omitted', 'matching', 'outside', 'empty', 'missing'):
                    with self.subTest(command=command[0], mode=mode), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                         patch('exposedapi.scanner.UrllibClient.get', return_value=HttpResponse(200, b'ok', {})) as get, \
                         patch('exposedapi.scanner._RateLimiter.wait'), patch('exposedapi.compare.time.sleep'):
                        output = root / f'{index}-{mode}.json'
                        args = command + ['--output', str(output)]
                        if mode != 'omitted':
                            scope.write_text({'matching': 'any.example', 'outside': 'other.example',
                                              'empty': '# no hosts\n', 'missing': ''}[mode])
                            args += ['--scope', str(root / 'missing' if mode == 'missing' else scope)]
                        if mode in ('empty', 'missing') or (mode == 'outside' and index in (0, 3)):
                            with self.assertRaises(SystemExit):
                                main(args)
                            get.assert_not_called()
                        else:
                            self.assertEqual(main(args), 0)
                            report = json.loads(output.read_text())
                            self.assertEqual(report['scope'], None if mode == 'omitted' else ['any.example' if mode == 'matching' else 'other.example'])
                            if mode == 'outside':
                                get.assert_not_called()
                            elif index != 1:
                                self.assertTrue(get.called)

    def test_scan_and_matrix_dry_runs_without_scope(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'MATRIX_AUTH': 'Bearer test'}), \
             patch('exposedapi.scanner.UrllibClient.get') as get, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            targets, matrix = root / 'targets', root / 'matrix.json'
            targets.write_text('https://any.example/item')
            matrix.write_text(json.dumps({'accounts': {'owner': {'headers_env': {'Authorization': 'MATRIX_AUTH'}}},
                                         'resources': [{'url': 'https://any.example/item', 'allowed_accounts': ['owner']}]}))
            for args in (['--targets', str(targets)], ['account-matrix', '--matrix', str(matrix)]):
                self.assertEqual(main(args + ['--dry-run', '--acknowledge-authorization']), 0)
            get.assert_not_called()
