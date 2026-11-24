import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pms_core as core
from pms_keymatch import jks_public_certificates, match_candidates, inspect_selected_branch


@unittest.skipUnless(shutil.which('keytool'), 'JDK keytool required')
class RealKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.vault=core.SigningVault(self.root/'vault')
        for name in ('dpapi_encrypt','dpapi_decrypt'):
            p=patch.object(core,name,side_effect=lambda b:b[::-1])
            p.start();self.addCleanup(p.stop)

    def make_jks(self, filename,alias):
        path=self.root/filename
        subprocess.run(['keytool','-genkeypair','-storetype','JKS','-keystore',str(path),
               '-alias',alias,'-keyalg','RSA','-keysize','2048','-validity','2',
               '-dname','CN=test','-storepass','testing1234','-keypass','testing1234',
               '-noprompt'],check=True,capture_output=True,text=True)
        return path

    def test_jks_certificate_matching_never_requires_password(self):
        orig=self.make_jks('owner.jks','ownerkey')
        different=self.make_jks('developer.jks','devkey')
        leaf=jks_public_certificates(orig)
        self.assertEqual(len(leaf),1)
        self.assertEqual(leaf[0].alias,'ownerkey')
        self.assertEqual(len(leaf[0].sha256),64)
        candidates=[core.KeyCandidate(orig,orig.stat().st_size),core.KeyCandidate(different,different.stat().st_size)]
        matched,unknown=match_candidates(candidates,leaf[0].sha256)
        self.assertEqual(len(matched),1)
        self.assertEqual(matched[0].path,orig)
        self.assertFalse(unknown)

    def test_original_can_coexist_with_wrong_previous_key(self):
        # Existing wrong signer is retained. Matching signer is stored separately.
        original=self.make_jks('original.jks','realowner')
        expected=jks_public_certificates(original)[0].sha256
        self.vault.create('com.example.app',confirm=True)
        self.assertNotEqual(self.vault.load('com.example.app').fingerprint,expected)
        with self.assertRaisesRegex(core.BuildError,'mismatch'):
            self.vault.import_existing('com.example.app',original,'realowner',
                'testing1234',expected_sha256='0'*64)
        self.assertIsNone(self.vault.load_for_certificate('com.example.app',expected))
        imported=self.vault.import_existing('com.example.app',original,'realowner',
            'testing1234',expected_sha256=expected)
        self.assertEqual(imported.fingerprint,expected)
        self.assertNotEqual(self.vault.load('com.example.app').fingerprint,expected)
        self.assertEqual(self.vault.load_for_certificate('com.example.app',expected).fingerprint,expected)
        self.assertTrue((self.root/'vault'/'alternatives'/'com.example.app'/expected/'identity.json').exists())
        with self.assertRaisesRegex(core.BuildError,'already saved'):
            self.vault.import_existing('com.example.app',original,'realowner',
                'testing1234',expected_sha256=expected)

    def test_unsafe_jks_scan_is_nonfatal(self):
        bad=self.root/'bad.jks';bad.write_bytes(b'\xfe\xed\xfe\xed')
        candidates=[core.KeyCandidate(bad,bad.stat().st_size)]
        matched,unknown=match_candidates(candidates,'1'*64)
        self.assertFalse(matched)
        self.assertEqual(len(unknown),1)


class SourceSelectionTests(unittest.TestCase):
    def test_inspect_branch_uses_recipe_and_preapproved_match(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            keys=root/'keys';keys.mkdir()
            cert='a'*64
            (keys/'owner.jks').write_bytes(b'jks-mock')
            recipe_file=root/'customer.pms-apk.json'
            recipe_file.write_text(__import__('json').dumps({'schema':1,'profiles':{'customer':{
               'projectType':'capacitor','package':'com.example.app','signerSha256':cert,
               'steps':{}}}}))
            def fake_clone(repo,branch,source,log=None):
                source.mkdir()
                (source/'package.json').write_text('{}')
                (source/'capacitor.config.json').write_text('{"appId":"com.example.app"}')
                return 'e'*40
            class FakeVault:
                def load_for_certificate(self,package,sha):return None
            with patch.object(core,'clone_branch',side_effect=fake_clone), \
                 patch('pms_keymatch.jks_public_certificates',return_value=(
                     __import__('pms_keymatch').CertificateHint('owner',cert),)):
                result=inspect_selected_branch('https://github.com/example/app','main',
                    recipe_profile='customer',recipe_file=recipe_file,vault=FakeVault(),folders=[keys])
            self.assertEqual(result.package,'com.example.app')
            self.assertEqual(result.expected_certificate,cert)
            self.assertEqual(len(result.matches),1)
            self.assertEqual(result.matches[0].alias,'owner')


if __name__=='__main__':unittest.main()
