import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import argparse
import os

spec = importlib.util.spec_from_file_location('files', Path(__file__).with_name('customer-files.py'))
files = importlib.util.module_from_spec(spec)
spec.loader.exec_module(files)

class FilesCLITest(unittest.TestCase):
    def test_upload_precheck_denies_existing_and_unknown_but_allows_missing(self):
        with patch.object(files, 'request', return_value=(200, b'')):
            with self.assertRaisesRegex(RuntimeError, 'already exists'):
                files.require_missing('https://files.example/dav/a', {})
        with patch.object(files, 'request', side_effect=RuntimeError('HTTP 403 (HEAD); response body omitted')):
            with self.assertRaisesRegex(RuntimeError, '403'):
                files.require_missing('https://files.example/dav/a', {})
        with patch.object(files, 'request', side_effect=RuntimeError('HTTP 404 (HEAD); response body omitted')):
            files.require_missing('https://files.example/dav/a', {})

    def test_path_encoding_and_traversal_denial(self):
        self.assertEqual(files.dav_address('https://files.example', 'personal-files', '合同 A/#1.txt'), 'https://files.example/dav/personal-files/%E5%90%88%E5%90%8C%20A/%231.txt')
        for value in ['../common-files/a', '/a', 'a/../b', 'a\\b']:
            with self.assertRaises(ValueError): files.dav_address('https://files.example', 'personal-files', value)

    def test_rejects_insecure_or_credential_bearing_servers(self):
        for value in ['http://files.example', 'https://u:secret@files.example', 'https://files.example/dav/', 'https://files.example?password=a']:
            with self.assertRaises(ValueError): files.server(value)

    @unittest.skipIf(os.name == 'nt', 'Unix file mode test')
    def test_file_storage_is_private_bound_to_server_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'credential.json')
            args = argparse.Namespace(credential_file=path, server='https://files.example')
            value = {'server':args.server, 'password':'synthetic'}
            files.credential(args, value)
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
            self.assertEqual(files.credential(args),value)
            with self.assertRaises(FileExistsError): files.credential(args, value)
            args.server='https://other.example'
            with self.assertRaises(RuntimeError): files.credential(args)

if __name__ == '__main__': unittest.main()
