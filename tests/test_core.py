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




class PortableSdkRegressionTests(unittest.TestCase):
    """Read-only SDK checks reproduce Windows SDK folder layouts on all CI hosts."""

    def make_sdk(self, root, version='35.0.0', *, windows=True, complete=True):
        sdk=Path(root)/'build-tools'/version
        sdk.mkdir(parents=True)
        suffix='.exe' if windows else ''
        for tool in ('aapt','zipalign'):
            (sdk/(tool+suffix)).write_text('placeholder')
        if complete:
            (sdk/('apksigner.bat' if windows else 'apksigner')).write_text('placeholder')
        return sdk

    def test_windows_apksigner_bat_is_required_not_exe(self):
        with tempfile.TemporaryDirectory() as d:
            sdk=self.make_sdk(d)
            found=core.sdk_tool_paths(sdk,windows=True)
            self.assertEqual(found['apksigner'].name,'apksigner.bat')
            self.assertTrue(all(p.is_file() for p in found.values()))
            (sdk/'apksigner.bat').unlink()
            self.assertFalse(all(p.is_file() for p in core.sdk_tool_paths(sdk,windows=True).values()))

    def test_explicit_root_and_fallback_between_incomplete_sdk_versions(self):
        with tempfile.TemporaryDirectory() as d:
            full=self.make_sdk(d,'34.0.0',windows=True)
            self.make_sdk(d,'35.0.0',windows=True,complete=False)
            found=core.sdk_build_tools(d,windows=True)
            self.assertEqual(found['aapt'].parent,full)
            self.assertEqual(found['apksigner'].name,'apksigner.bat')

    def test_explicit_sdk_root_never_silently_falls_back_elsewhere(self):
        with tempfile.TemporaryDirectory() as d:
            one=Path(d)/'wrong'
            two=Path(d)/'real'
            self.make_sdk(two,windows=True)
            with patch.dict(os.environ,{'ANDROID_SDK_ROOT':str(two)}):
                with self.assertRaisesRegex(core.BuildError,'Select your Android SDK'):
                    core.sdk_build_tools(one)

    def test_android_sdk_from_localappdata_and_alternative_profile(self):
        with tempfile.TemporaryDirectory() as d:
            local=Path(d)/'AppData'/'Local'
            expected=local/'Android'/'Sdk'
            self.make_sdk(expected,windows=True)
            with patch.dict(os.environ,{'LOCALAPPDATA':str(local), 'ANDROID_SDK_ROOT':'',
                'ANDROID_HOME':'', 'PMS_ANDROID_SDK_ROOT':''}):
                self.assertIn(expected,core.sdk_candidates())

    def test_browser_tree_link_extracts_branch_without_relaxing_origin(self):
        clone,slug,branch=core.parse_repo_selection(
            'https://github.com/owner/example-repo/tree/feature/premium-glass-2026')
        self.assertEqual((clone,slug,branch),(
            'https://github.com/owner/example-repo.git','owner/example-repo','feature/premium-glass-2026'))
        self.assertEqual(core.validate_repo('https://github.com/owner/example-repo/tree/main'),
                         (clone,slug))
        for value in ('https://github.com/owner/repo/blob/main/file',
                      'https://github.com/owner/repo/tree/a/../b',
                      'https://github.com/owner/repo/tree/a?token=123',
                      'https://github.com/owner/repo/tree/a%2Fb',
                      'https://github.com.evil.com/owner/repo/tree/main'):
            with self.subTest(value=value),self.assertRaises(core.BuildError):
                core.parse_repo_selection(value)

    def test_sdk_failure_does_not_create_or_regenerate_keys(self):
        with tempfile.TemporaryDirectory() as d:
            original=Path(d)/'signing'
            vault=core.SigningVault(original)
            with self.assertRaisesRegex(core.BuildError,'Android SDK Build Tools'):
                core.create_release('https://github.com/owner/repo','main',Path(d),
                                    vault,sdk_root=Path(d)/'missing-sdk')
            self.assertFalse(original.exists())

if __name__=='__main__':unittest.main()


class SigningKeyDiscoveryTests(unittest.TestCase):
    def test_discovery_scans_user_folders_and_skips_non_keys_and_hidden_repos(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            download=home/'Downloads'/'my-android'/'android'/'app'
            download.mkdir(parents=True)
            legacy=download/'release-upload.jks';legacy.write_bytes(b'FAKE JKS TEST PLACEHOLDER')
            (download/'notes.txt').write_text('not a key')
            git=download/'.git';git.mkdir()
            (git/'private.p12').write_bytes(b'not a key')
            printmarks=home/'AppData'/'Local'/'Printmarks'/'SINGOKEY'/'Developer-Private'
            printmarks.mkdir(parents=True)
            other=printmarks/'owner-release.P12';other.write_bytes(b'NOT A REAL KEY')
            with patch.object(core.Path,'home',return_value=home):
                result=core.discover_signing_keys()
            self.assertEqual({i.path for i in result.candidates},{legacy,other})
            self.assertFalse(result.limited)
            self.assertTrue(all(i.size_bytes>0 for i in result.candidates))

    def test_custom_folder_and_optional_limited_search(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'one.keystore').write_bytes(b'not a secret')
            (root/'two.pfx').write_bytes(b'not a secret')
            results=core.discover_signing_keys([root],max_results=1)
            self.assertEqual(len(results.candidates),1)
            self.assertTrue(results.limited)
            results2=core.discover_signing_keys([root],max_entries=1)
            self.assertTrue(results2.limited)
            self.assertLessEqual(len(results2.candidates),1)

    def test_unsafe_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/'source';source.mkdir()
            remote=root/'remote';remote.mkdir()
            (remote/'original.jks').write_bytes(b'test only')
            try:(source/'shortlink').symlink_to(remote,target_is_directory=True)
            except (OSError,NotImplementedError):self.skipTest('Symlink unavailable')
            found=core.discover_signing_keys([source])
            self.assertEqual(found.candidates,())

    def test_search_does_not_read_private_key_content(self):
        with tempfile.TemporaryDirectory() as td:
            key=Path(td)/'secret.jks';key.write_bytes(b'only a pathname should be scanned')
            with patch.object(Path,'read_bytes',side_effect=AssertionError('key content read')):
                self.assertEqual(len(core.discover_signing_keys([Path(td)]).candidates),1)


class GradleSdkEnvironmentTests(unittest.TestCase):
    def test_local_properties_preserves_other_values_and_replaces_stale_sdk(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            android=root/'source'/'android';android.mkdir(parents=True)
            sdk=root/'Android'/'Sdk';(sdk/'build-tools').mkdir(parents=True)
            props=android/'local.properties'
            props.write_text('ndk.dir=/other/ndk\nsdk.dir=C:/old/sdk\ncustom=value\n','utf8')
            core.configure_gradle_sdk(android,sdk)
            result=props.read_text('utf8')
            self.assertIn('sdk.dir='+sdk.as_posix(),result)
            self.assertEqual(result.count('sdk.dir='),1)
            self.assertIn('ndk.dir=/other/ndk',result)
            self.assertIn('custom=value',result)

    def test_gradle_builder_receives_local_properties(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            android=root/'android';android.mkdir()
            sdk=root/'sdk';(sdk/'build-tools').mkdir(parents=True)
            (android/'gradlew.bat').write_text('@echo off\n')
            (android/'gradlew').write_text('#!/bin/sh\n')
            with patch.object(core,'run') as subprocess_stub:
                core.build_source(root,'gradle-android',env={'ANDROID_HOME':str(sdk)},sdk_root=sdk)
            self.assertIn('sdk.dir='+sdk.as_posix(),(android/'local.properties').read_text('utf8'))
            self.assertEqual(subprocess_stub.call_count,1)
            self.assertEqual(subprocess_stub.call_args.kwargs['env']['ANDROID_HOME'],str(sdk))

    def test_gradle_rejects_linked_local_properties(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            android=root/'android';android.mkdir()
            sdk=root/'sdk';(sdk/'build-tools').mkdir(parents=True)
            outside=root/'original.properties';outside.write_text('do not modify')
            try:(android/'local.properties').symlink_to(outside)
            except (OSError,NotImplementedError):self.skipTest('Symlink unavailable')
            with self.assertRaisesRegex(core.BuildError,'Unsafe'):
                core.configure_gradle_sdk(android,sdk)
            self.assertEqual(outside.read_text(),'do not modify')


@unittest.skipUnless(shutil.which('keytool'), 'JDK keytool required')
class OriginalJksSigningImportTests(unittest.TestCase):
    def test_import_original_jks_with_distinct_store_and_key_password(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/'existing-owner.jks'
            env=os.environ.copy()
            env['PMS_SRC_STORE']='test-store-password-123'
            env['PMS_SRC_KEY']='test-key-password-456'
            subprocess.run([shutil.which('keytool'),'-genkeypair','-keyalg','RSA',
                '-keysize','2048','-storetype','JKS','-keystore',str(source),
                '-alias','original.owner','-dname','CN=Signing Test',
                '-validity','365', '-storepass:env','PMS_SRC_STORE',
                '-keypass:env','PMS_SRC_KEY','-noprompt'],env=env,check=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            vault=core.SigningVault(root/'vault')
            with patch.object(core,'dpapi_encrypt',side_effect=lambda b:b[::-1]), \
                 patch.object(core,'dpapi_decrypt',side_effect=lambda b:b[::-1]):
                imported=vault.import_existing('com.example.released',source,
                  'original.owner','test-store-password-123',key_password='test-key-password-456')
                self.assertNotEqual(imported.password,'test-store-password-123')
                self.assertTrue(imported.keystore.exists())
                self.assertEqual(vault.load('com.example.released').fingerprint,imported.fingerprint)
                with self.assertRaises(core.BuildError):
                    vault.import_existing('com.example.released',source,
                      'original.owner','test-store-password-123','test-key-password-456')


class ReleaseSdkHandoffTests(unittest.TestCase):
    def test_detected_sdk_root_is_passed_to_gradle_subprocess(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            sdk=root/'Sdk'; buildtools=sdk/'build-tools'/'36.0.0';buildtools.mkdir(parents=True)
            aapt=buildtools/'aapt.exe';aapt.write_bytes(b'aapt')
            aligned={name:buildtools/name for name in ('aapt.exe','zipalign.exe','apksigner.bat')}
            env_seen=[]
            def fake_build(src,kind,log=None,env=None,sdk_root=None):
                self.assertEqual(str(sdk),str(sdk_root))
                self.assertEqual(env['ANDROID_HOME'],str(sdk))
                self.assertEqual(env['ANDROID_SDK_ROOT'],str(sdk))
                env_seen.append(True)
            def fake_clone(repo,branch,src,log=None):
                src.mkdir(parents=True)
                return 'a'*40
            mocked_vault=MagicMock()
            mocked_vault.load.return_value=core.Identity('com.example.app','release', 'c'*64,root/'release.p12','test')
            def fake_signed(source_apk,package,identity,dest,sdk,log=None):
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(b'unit test only')
                return 'a'*64
            with patch.object(core,'sdk_build_tools',return_value={
                    'aapt':aligned['aapt.exe'],'zipalign':aligned['zipalign.exe'],'apksigner':aligned['apksigner.bat']}),\
                 patch.object(core,'clone_branch',side_effect=fake_clone),\
                 patch.object(core,'detect_project',return_value='gradle-android'),\
                 patch.object(core,'build_source',side_effect=fake_build),\
                 patch.object(core,'choose_apk',return_value=root/'fake.apk'),\
                 patch.object(core,'apk_package',return_value='com.example.app'),\
                 patch.object(core,'signed_apk',side_effect=fake_signed),\
                 patch.object(core.SecretVault,'values',return_value={}):
                result=core.create_release('https://github.com/owner/project','main',root/'output',mocked_vault)
            self.assertEqual(len(env_seen),1)
            self.assertEqual(result['projectType'],'gradle-android')


class SigningPreflightTests(unittest.TestCase):
    def test_literal_capacitor_package_hint_and_dynamic_config(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            ts=root/'capacitor.config.ts'
            ts.write_text("import type {CapacitorConfig} from '@capacitor/cli';\n"
                          "const config:CapacitorConfig={appId:'com.mjranuda.karaokey',appName:'Test'};\n"
                          "export default config;\n",encoding='utf8')
            self.assertEqual(core.source_package_hint(root,'capacitor'),'com.mjranuda.karaokey')
            ts.write_text("const config={appId:process.env.APP_ID};\n",encoding='utf8')
            self.assertIsNone(core.source_package_hint(root,'capacitor'))
            ts.unlink()
            (root/'capacitor.config.json').write_text('{"appId":"com.example.other"}',encoding='utf8')
            self.assertEqual(core.source_package_hint(root,'capacitor'),'com.example.other')

    def test_gradle_hint_skips_flavors_and_suffixes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            gradle=root/'android'/'app'/'build.gradle'
            gradle.parent.mkdir(parents=True)
            gradle.write_text("android { defaultConfig { applicationId 'com.example.app' } }",encoding='utf8')
            self.assertEqual(core.source_package_hint(root,'gradle-android'),'com.example.app')
            gradle.write_text("android { defaultConfig { applicationId 'com.example.app' } "
                              "productFlavors { dev { applicationIdSuffix '.dev' } } }",encoding='utf8')
            self.assertIsNone(core.source_package_hint(root,'gradle-android'))

    def test_preflight_detects_missing_signer_before_any_build(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            sdk=root/'sdk'/'build-tools'/'36.0.0'
            sdk.mkdir(parents=True)
            stub={'aapt':sdk/'aapt.exe','zipalign':sdk/'zipalign.exe','apksigner':sdk/'apksigner.bat'}
            def clone(repo,branch,checkout,log=None):
                checkout.mkdir()
                (checkout/'package.json').write_text('{}')
                (checkout/'capacitor.config.ts').write_text("export default {appId:'com.example.existing'}")
                return 'a'*40
            with patch.object(core,'sdk_build_tools',return_value=stub),\
                 patch.object(core,'clone_branch',side_effect=clone),\
                 patch.object(core,'build_source',side_effect=AssertionError('build must not run')),\
                 patch.object(core.SecretVault,'values',side_effect=AssertionError('secret lookup must not run')):
                vault=MagicMock()
                vault.load.return_value=None
                with self.assertRaisesRegex(core.BuildError,'BEFORE npm/Gradle'):
                    core.create_release('https://github.com/owner/project','main',root/'out',vault)
                self.assertEqual(vault.load.call_args.args[0],'com.example.existing')

    def test_selected_package_must_match_source_even_with_new_signing_approval(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'capacitor.config.ts').write_text("const config={appId:'com.example.customer'};")
            vault=MagicMock()
            with self.assertRaisesRegex(core.BuildError,'does not match source application ID'):
                core.preflight_signer(root,'capacitor',vault,expected_package='com.example.dev',allow_new_key=True)
            vault.load.assert_not_called()

    def test_imported_signer_matches_old_apk_or_stops(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            apk=Path(td)/'old-signed.apk';apk.write_bytes(b'fixture')
            vault=MagicMock()
            vault.load.return_value=core.Identity('com.example.customer','myalias','f'*64,
                                                   Path(td)/'saved.p12','test')
            fake_sdk={k:Path(td)/k for k in ('aapt','zipalign','apksigner')}
            with patch.object(core,'apk_package',return_value='com.example.customer'),\
                 patch.object(core,'run',return_value='Signer #1 certificate SHA-256 digest: '+'f'*64):
                fingerprint=core.verify_signer_against_original_apk(
                    apk,'com.example.customer',vault,sdk=fake_sdk)
                self.assertEqual(fingerprint,'f'*64)
            with patch.object(core,'apk_package',return_value='com.example.customer'),\
                 patch.object(core,'run',return_value='Signer #1 certificate SHA-256 digest: '+'e'*64):
                with self.assertRaisesRegex(core.BuildError,'SIGNER MISMATCH'):
                    core.verify_signer_against_original_apk(apk,'com.example.customer',vault,sdk=fake_sdk)
            with patch.object(core,'apk_package',return_value='com.example.dev'),\
                 patch.object(core,'run',side_effect=AssertionError('should not verify unrelated APK')):
                with self.assertRaisesRegex(core.BuildError,'package does not match'):
                    core.verify_signer_against_original_apk(apk,'com.example.customer',vault,sdk=fake_sdk)
