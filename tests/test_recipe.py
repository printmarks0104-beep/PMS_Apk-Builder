import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pms_recipe as r
import pms_core as core


class RecipeTests(unittest.TestCase):
    def make_tree(self, root, profiles=None):
        (root/'native').mkdir(exist_ok=True)
        (root/'scripts').mkdir(exist_ok=True)
        (root/'scripts'/'prepare-android.mjs').write_text('console.log("test")')
        if profiles is not None:
            (root/'.pms-apk.json').write_text(json.dumps({'schema':1,'profiles':profiles}))

    def profile(self):
        return {'projectType':'capacitor','package':'com.example.music',
                'signerSha256':'a'*64, 'minApkBytes':30000000,
                'environment':{'RELEASE_PROFILE':'customer'},
                'requiredEnvironment':['ORIGINAL_PUBLIC_KEY'],
                'steps':{'afterSync':[['node','scripts/prepare-android.mjs']],
                         'afterSign':[['python','scripts/verify.py','{apk}']]}}

    def test_no_recipe_rejects_native_capacitor_shell(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.make_tree(root)
            with self.assertRaisesRegex(r.RecipeError,'incomplete APK'):
                r.load_recipe(root)

    def test_generic_capacitor_without_native_scripts_remains_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(r.load_recipe(Path(d)))

    def test_recipe_profile_selection_and_env_validation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.make_tree(root,{'customer':self.profile(),'developer':self.profile()})
            with self.assertRaisesRegex(r.RecipeError,'Choose a recipe profile'):r.load_recipe(root)
            recipe=r.load_recipe(root,'customer')
            self.assertEqual(recipe.min_apk_bytes,30000000)
            with self.assertRaisesRegex(r.RecipeError,'Required build configuration is missing'):
                r.recipe_env(recipe,{}, {'CM_KEYSTORE_PATH':'vault-key'})
            env=r.recipe_env(recipe,{'ORIGINAL_PUBLIC_KEY':'test-only'}, {'CM_KEYSTORE_PATH':'vault-key'})
            self.assertEqual(env['CM_KEYSTORE_PATH'],'vault-key')
            self.assertEqual(env['RELEASE_PROFILE'],'customer')

    def test_reject_recipe_environment_override_of_signing_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.profile();p['environment']['CM_KEYSTORE_PATH']='./fake'
            self.make_tree(root,{'customer':p})
            with self.assertRaisesRegex(r.RecipeError,'reserved'):r.load_recipe(root)

    def test_reject_shell_command_or_bad_schema(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.profile();p['steps']['beforeSync']=[['cmd','/c','echo','bad']]
            self.make_tree(root,{'customer':p})
            with self.assertRaisesRegex(r.RecipeError,'executable'):r.load_recipe(root)
            (root/'.pms-apk.json').write_text('{"schema":2,"profiles":{}}')
            with self.assertRaisesRegex(r.RecipeError,'schema'):r.load_recipe(root)

    def test_recipe_execution_preserves_stage_order_and_apk_path(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.make_tree(root,{'customer':self.profile()})
            recipe=r.load_recipe(root)
            called=[]
            def run(args,**kw):called.append((args,kw['cwd'],kw['env']['RELEASE_PROFILE']))
            r.run_recipe_stage(recipe,'afterSync',root,{'RELEASE_PROFILE':'customer'},lambda x:x,run)
            r.run_recipe_stage(recipe,'afterSign',root,{'RELEASE_PROFILE':'customer'},lambda x:x,run,apk=root/'ready.apk')
            self.assertEqual(called[0][0],['node','scripts/prepare-android.mjs'])
            self.assertEqual(called[1][0][-1],str(root/'ready.apk'))

    def test_recipe_pinned_signer_refused_before_any_build_steps(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'source').mkdir();src=root/'source'
            self.make_tree(src,{'customer':self.profile()})
            (src/'capacitor.config.ts').write_text('appId: "com.example.music"')
            (src/'package.json').write_text('{}')
            class Vault:
                def load(self,package):return SimpleNamespace(fingerprint='b'*64)
            with patch.object(core,'sdk_build_tools',return_value={'aapt':root/'Sdk/build-tools/35/aapt'}),\
                 patch.object(core,'clone_branch',return_value='f'*40),\
                 patch.object(core,'detect_project',return_value='capacitor'),\
                 patch.object(core,'build_source') as build,\
                 patch.object(core.tempfile,'TemporaryDirectory') as td:
                td.return_value.__enter__.return_value=str(root)
                # src already exists via the mocked clone.
                with self.assertRaisesRegex(core.BuildError,'SIGNER MISMATCH'):
                    core.create_release('https://github.com/org/app','main',root/'output',Vault())
                build.assert_not_called()

    def test_recipe_pinned_signer_refuses_new_key_generation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'source';src.mkdir()
            self.make_tree(src,{'customer':self.profile()})
            (src/'capacitor.config.ts').write_text('appId:"com.example.music"')
            (src/'package.json').write_text('{}')
            class Vault:
                def load(self,package):return None
            with patch.object(core,'sdk_build_tools',return_value={'aapt':root/'Sdk/build-tools/35/aapt'}),\
                 patch.object(core,'clone_branch',return_value='f'*40),\
                 patch.object(core,'detect_project',return_value='capacitor'),\
                 patch.object(core,'build_source') as build,\
                 patch.object(core.tempfile,'TemporaryDirectory') as td:
                td.return_value.__enter__.return_value=str(root)
                with self.assertRaisesRegex(core.BuildError,'New-key generation is forbidden'):
                    core.create_release('https://github.com/org/app','main',root/'output',Vault(),allow_new_key=True)
                build.assert_not_called()

if __name__=='__main__':unittest.main()

class ExternalRecipeTests(unittest.TestCase):
    def test_external_file_is_used_without_mutating_source_branch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'checked-out-app';root.mkdir()
            (root/'native').mkdir()
            (root/'scripts').mkdir()
            (root/'scripts'/'prepare-android.mjs').write_text('native-setup')
            original=set(root.rglob('*'))
            local=Path(d)/'trusted-local-recipe.json'
            local.write_text(json.dumps({'schema':1,'profiles':{'release':{
                'projectType':'capacitor','package':'com.example.app',
                'steps':{'afterSync':[['node','scripts/prepare-android.mjs']]}
            }}}))
            recipe=r.load_recipe(root,'auto',external_file=local)
            self.assertEqual(recipe.profile,'release')
            self.assertEqual(set(root.rglob('*')),original)
            self.assertFalse((root/'.pms-apk.json').exists())

    def test_invalid_external_path_does_not_fallback_to_generic(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(r.RecipeError,'not found'):
                r.load_recipe(Path(d),external_file=Path(d)/'missing-recipe.json')

    def test_temporary_runtime_path_expansion(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';source.mkdir()
            recipe=r.Recipe('customer','capacitor','com.example.app',None,100000,
                {'RUNTIME_FOLDER':'{source}/.private-cache'},(),{n:() for n in r.STAGES})
            env=r.recipe_env(recipe,{}, {},source_root=source)
            self.assertEqual(env['RUNTIME_FOLDER'],str(source.resolve())+'/.private-cache')
