"""Repository-owned Android build recipes for PMS APK Builder.

No project logic is bundled in PMS: the repository declares the exact preparation,
profile, and verification commands it needs. A recipe runs only from the selected
checked-out Git revision and can execute code; use trusted repositories only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class RecipeError(ValueError):
    pass


STAGES = ('beforeSync', 'afterSync', 'beforeGradle', 'afterSign')
_SAFE_ID = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_SAFE_PROFILE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,63}$')
_PACKAGE = re.compile(r'^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$')
_SHA = re.compile(r'^[a-f0-9]{64}$')
_ALLOWED_TOOLS = frozenset(('node','python','npm','npx','flutter','java','keytool'))
_ALLOWED_FIELDS = frozenset(('projectType','package','signerSha256','minApkBytes',
                             'environment','requiredEnvironment','steps'))
_DISALLOWED_ENV = frozenset(('PATH','PATHEXT','JAVA_HOME','ANDROID_HOME',
    'ANDROID_SDK_ROOT','CM_KEYSTORE_PATH','CM_KEYSTORE_PASSWORD','CM_KEY_PASSWORD',
    'CM_KEY_ALIAS','KARAOKEY_SIGNING_CERT_SHA256','PMS_SIGNING_PASSWORD',
    'GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','PYTHONPATH','NODE_OPTIONS',
    'GRADLE_OPTS','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS'))


@dataclass(frozen=True)
class Recipe:
    profile: str
    project_type: str
    package: str
    signer_sha256: str | None
    min_apk_bytes: int
    environment: dict[str,str]
    required_environment: tuple[str,...]
    steps: dict[str,tuple[tuple[str,...],...]]


def requires_native_recipe(root:Path)->bool:
    """Distinguish a custom Android-native app from an ordinary Capacitor shell."""
    root=Path(root)
    return (root/'native').is_dir() and (root/'scripts'/'prepare-android.mjs').is_file()


def _checked_command(value)->tuple[str,...]:
    if not isinstance(value,list) or not (2<=len(value)<=20) or \
            not all(isinstance(x,str) and 0<len(x)<=512 and '\x00' not in x for x in value):
        raise RecipeError('Each recipe command must be a short string-argument array')
    if value[0] not in _ALLOWED_TOOLS:
        raise RecipeError('Recipe executable not supported: '+str(value[0]))
    if any(x in ('{', '}', '{apk', '{root') for x in value[1:]):
        raise RecipeError('Recipe placeholders must be exact {apk} or {root} arguments')
    return tuple(value)


def load_recipe(root:Path, selected_profile:str='auto', external_file:Path|None=None)->Recipe|None:
    root=Path(root)
    cfg=Path(external_file).expanduser() if external_file is not None else root/'.pms-apk.json'
    if not cfg.is_file():
        if external_file is not None:
            raise RecipeError('Selected external build recipe file was not found')
        if requires_native_recipe(root):
            raise RecipeError('This repository contains custom native Android preparation but no '
                '.pms-apk.json build recipe. Generic Capacitor builds omit native plugins; '
                'refusing to produce an incomplete APK.')
        return None
    if cfg.is_symlink() or cfg.stat().st_size>64*1024:
        raise RecipeError('Repository APK build recipe must be a normal file under 64 KiB')
    try:data=json.loads(cfg.read_text('utf8'))
    except (ValueError,UnicodeError) as e:raise RecipeError('Invalid .pms-apk.json') from e
    if not isinstance(data,dict) or data.get('schema')!=1 or \
        set(data)-{'schema','profiles'} or not isinstance(data.get('profiles'),dict):
        raise RecipeError('Unsupported .pms-apk.json schema (expected schema 1 with profiles)')
    profiles=data['profiles']
    if not 1<=len(profiles)<=12 or not all(_SAFE_PROFILE.fullmatch(str(x)) for x in profiles):
        raise RecipeError('Invalid recipe profiles')
    if selected_profile in ('','auto'):
        if len(profiles)!=1:
            raise RecipeError('Choose a recipe profile: '+', '.join(sorted(profiles)))
        selected_profile=next(iter(profiles))
    if selected_profile not in profiles:
        raise RecipeError('Unknown recipe profile '+str(selected_profile)+'; available: '+', '.join(sorted(profiles)))
    p=profiles[selected_profile]
    if not isinstance(p,dict) or set(p)-_ALLOWED_FIELDS:
        raise RecipeError('Unknown recipe fields in profile '+selected_profile)
    project_type=p.get('projectType')
    if project_type not in ('capacitor','flutter','gradle','gradle-android'):
        raise RecipeError('Unsupported recipe project type')
    package=p.get('package')
    if not isinstance(package,str) or not _PACKAGE.fullmatch(package):
        raise RecipeError('Recipe package ID is invalid')
    cert=p.get('signerSha256')
    if cert is not None and (not isinstance(cert,str) or not _SHA.fullmatch(cert)):
        raise RecipeError('Recipe signerSha256 must be a lower-case 64-digit hex fingerprint')
    minsize=p.get('minApkBytes',0)
    if type(minsize)!=int or minsize<0 or minsize>2*1024*1024*1024:
        raise RecipeError('Recipe minApkBytes is invalid')
    env=p.get('environment',{})
    if not isinstance(env,dict) or len(env)>50:
        raise RecipeError('Recipe environment must be an object')
    for name,value in env.items():
        if not _SAFE_ID.fullmatch(name) or name in _DISALLOWED_ENV or name.startswith('PMS_') or \
                not isinstance(value,str) or len(value)>4096 or '\x00' in value:
            raise RecipeError('Invalid or reserved recipe environment variable: '+str(name))
    required=p.get('requiredEnvironment',[])
    if not isinstance(required,list) or len(required)>50 or not all(isinstance(x,str)
            and _SAFE_ID.fullmatch(x) and x not in _DISALLOWED_ENV for x in required):
        raise RecipeError('Invalid requiredEnvironment list')
    steps=p.get('steps',{})
    if not isinstance(steps,dict) or set(steps)-set(STAGES):
        raise RecipeError('Unknown recipe step stage')
    valid_steps={}
    for stage in STAGES:
        entries=steps.get(stage,[])
        if not isinstance(entries,list) or len(entries)>24:
            raise RecipeError('Too many recipe steps in '+stage)
        valid_steps[stage]=tuple(_checked_command(v) for v in entries)
    return Recipe(selected_profile,project_type,package,cert,minsize,dict(env),
                  tuple(required),valid_steps)


def recipe_env(recipe:Recipe, inherited:dict[str,str], signing:dict[str,str],
               source_root:Path|None=None) -> dict[str,str]:
    env=dict(inherited)
    # Existing repository build secrets are kept, but fixed profile defaults are
    # declared explicitly and cannot be changed by source-controlled build code.
    for name, value in recipe.environment.items():
        if '{source}' in value:
            if source_root is None:raise RecipeError('Recipe source directory was not supplied')
            value=value.replace('{source}',str(Path(source_root).resolve()))
        env[name]=value
    env.update(signing)
    missing=[x for x in recipe.required_environment if not env.get(x)]
    if missing:
        raise RecipeError('Required build configuration is missing: '+', '.join(missing)+
            '. Save these values in the encrypted repository build-secret vault.')
    return env


def run_recipe_stage(recipe:Recipe, stage:str, src:Path, env:dict[str,str],
                     tool_resolver:Callable, runner:Callable, *, apk:Path|None=None, log=None)->None:
    if stage not in STAGES:raise RecipeError('Invalid recipe stage')
    for command in recipe.steps[stage]:
        args=[str(apk) if a=='{apk}' else str(src) if a=='{root}' else a for a in command[1:]]
        if '{apk}' in command[1:] and apk is None:
            raise RecipeError('APK is not available for stage '+stage)
        executable=command[0]
        if executable in ('npm','npx'):
            executable=executable+'.cmd' if __import__('os').name=='nt' else executable
        target=tool_resolver(executable)
        if log:log('Recipe ['+stage+']: '+command[0]+' '+command[1])
        runner([target,*args],cwd=src,env=env,log=log)
