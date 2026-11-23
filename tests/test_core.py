import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import pms_core as core


class ValidatorTests(unittest.TestCase):
    def test_github_url_canonical(self):
        self.assertEqual(core.validate_repo('https://github.com/owner/my-app'),
                         ('https://github.com/owner/my-app.git','owner/my-app'))
        self.assertEqual(core.validate_repo('https://github.com/owner/my-app.git'),
                         ('https://github.com/owner/my-app.git','owner/my-app'))

    def test_bad_repos_rejected(self):
        for url in ['http://github.com/foo/bar','https://evil.com/foo/bar',
                    'https://github.com/foo/bar?token=PRIVATE','file:///tmp/app',
                    'https://github.com/foo/../bar','https://github.com/foo/.git',
                    'https://github.com/-evil/repo']:
            with self.subTest(url=url),self.assertRaises(core.BuildError):core.validate_repo(url)

    def test_safe_branch_names(self):
        for value in ['main','fix/settings-2026','feature/ui.v2','release/1.0']:
            self.assertEqual(core.validate_branch(value),value)
        for value in ['','-bad','foo..bar','a//b','a/.git','x.lock','a@{b}',
                      'a b','a;echo hi','/root','a\\b']:
            with self.subTest(value=value),self.assertRaises(core.BuildError):core.validate_branch(value)

    def test_package_id(self):
        self.assertEqual(core.validate_package_id('com.example.test'),'com.example.test')
        for v in ['', 'foo', 'not legal.id','com.a-b','com.1demo']:
            with self.assertRaises(core.BuildError):core.validate_package_id(v)

    def test_detection_and_output_ambiguity(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'android').mkdir()
            (root/'pubspec.yaml').write_text('name: sample\n')
            self.assertEqual(core.detect_project(root),'flutter')
            self.assertEqual(core.detect_project(root,'flutter'),'flutter')
            with self.assertRaises(core.BuildError):core.detect_project(root,'capacitor')
            a=root/'build/app/outputs/flutter-apk/app-release.apk';a.parent.mkdir(parents=True)
            a.write_bytes(b'demo')
            b=root/'android/app/build/outputs/apk/release/app-release.apk';b.parent.mkdir(parents=True)
            b.write_bytes(b'demo')
            self.assertEqual(core.choose_apk(root),a.resolve())
            (root/'build/app/outputs/flutter-apk/app-release-2.apk').write_bytes(b'demo')
            with self.assertRaises(core.BuildError):core.choose_apk(root)

    def test_github_secret_upload_requires_opt_in(self):
        with self.assertRaisesRegex(core.BuildError,'approval'):
            core.publish_github_secrets('https://github.com/owner/repo','com.example.test',core.SigningVault(),confirm=False)

    def test_repository_build_secrets_names_restrictions(self):
        with tempfile.TemporaryDirectory() as td:
            v=core.SecretVault(Path(td))
            with self.assertRaises(core.BuildError):
                v.set('https://github.com/owner/repo','API_TOKEN','safe',confirm=False)
            for name in ('PATH','JAVA_HOME','NODE_OPTIONS','PMS_SIGNING_PASSWORD','a_key'):
                with self.assertRaises(core.BuildError):
                    v.set('https://github.com/owner/repo',name,'safe',confirm=True)

    def test_create_identity_needs_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            vault=core.SigningVault(Path(td))
            with self.assertRaisesRegex(core.BuildError,'approval'):vault.create('com.example.demo')


@unittest.skipUnless(shutil.which('keytool'), 'JDK keytool required')
class SigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.vault=core.SigningVault(self.root/'vault')
        self.patcher1=patch.object(core,'dpapi_encrypt',side_effect=lambda b: b[::-1])
        self.patcher2=patch.object(core,'dpapi_decrypt',side_effect=lambda b: b[::-1])
        self.patcher1.start();self.patcher2.start()
        self.addCleanup(self.patcher1.stop);self.addCleanup(self.patcher2.stop)

    def make_identity(self):
        # Test stub replaces Windows DPAPI only; real JDK creates/verifies PKCS12.
        return self.vault.create('com.example.demo',confirm=True)

    def test_create_reuse_and_never_overwrite(self):
        a=self.make_identity()
        b=self.vault.load('com.example.demo')
        self.assertEqual(a.fingerprint,b.fingerprint)
        self.assertEqual(a.password,b.password)
        with self.assertRaises(core.BuildError):self.vault.create('com.example.demo',confirm=True)
        self.assertEqual(a.fingerprint,self.vault.load('com.example.demo').fingerprint)

    def test_build_env_secret_encryption_and_backup(self):
        repo='https://github.com/owner/project'
        vault=core.SecretVault(self.root/'secrets')
        vault.set(repo,'PAYMENTS_PUBLIC_TOKEN','demo-testing-only',confirm=True)
        self.assertEqual(vault.names(repo),['PAYMENTS_PUBLIC_TOKEN'])
        self.assertNotIn('demo-testing-only',next((self.root/'secrets').iterdir()).read_text('utf8'))
        self.assertEqual(vault.values(repo)['PAYMENTS_PUBLIC_TOKEN'],'demo-testing-only')
        with self.assertRaises(core.BuildError):vault.set(repo,'PAYMENTS_PUBLIC_TOKEN','another',confirm=True)
        backup=self.root/'repo.pmsenv'
        vault.backup(repo,backup,'secret-test-passphrase')
        self.assertNotIn('demo-testing-only',backup.read_text('utf8'))
        recovered=core.SecretVault(self.root/'new-repo-vault')
        with self.assertRaises(core.BuildError):recovered.restore(backup,repo,'wrong')
        recovered.restore(backup,repo,'secret-test-passphrase')
        self.assertEqual(recovered.values(repo),vault.values(repo))
        with self.assertRaises(core.BuildError):recovered.restore(backup,repo,'secret-test-passphrase')

    def test_rename_or_modify_keystore_rejected(self):
        i=self.make_identity()
        i.keystore.write_bytes(i.keystore.read_bytes()+b'evil')
        with self.assertRaisesRegex(core.BuildError,'integrity'):self.vault.load('com.example.demo')

    def test_encrypted_backup_restore_and_wrong_password(self):
        a=self.make_identity()
        dest=self.root/'transfer.pmskey'
        self.vault.backup(a.package,dest,'a-strong-test-passphrase')
        self.assertNotIn(a.password,dest.read_text('utf8'))
        self.assertNotIn('MII',dest.read_text('utf8'))
        target=core.SigningVault(self.root/'newPC')
        with self.assertRaises(core.BuildError):target.restore(dest,'wrong-password')
        b=target.restore(dest,'a-strong-test-passphrase')
        self.assertEqual(a.fingerprint,b.fingerprint)
        self.assertEqual(a.password,b.password)
        with self.assertRaises(core.BuildError):target.restore(dest,'a-strong-test-passphrase')


if __name__=='__main__':unittest.main()
