"""Portable APK build/sign engine: no application-specific branches, files, or keys."""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pms_recipe import RecipeError, load_recipe, recipe_env, run_recipe_stage

VERSION = '0.1.5'
BACKUP_AAD = b'PMS-APK-BUILDER-KEY-BACKUP-V1'
PKG_RE = re.compile(r'^[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+$')
BRANCH_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,198}$')
GITHUB_RE = re.compile(r'^https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$', re.I)
HEX40 = re.compile(r'^[a-f0-9]{40}$')


class BuildError(Exception):
    """Expected fail-closed error; credentials must not be included in messages."""


def parse_repo_selection(value: str) -> tuple[str, str, str | None]:
    """Understand a GitHub repo URL or a GitHub browser branch URL.

    A branch URL has /tree/<branch>, including slash-separated branch names.
    Reject credentials, fragments, query strings, escape codes and other hosts.
    """
    input_url=str(value).strip()
    parsed=urlparse(input_url)
    if (parsed.scheme!='https' or parsed.netloc.lower()!='github.com' or
            parsed.username or parsed.password or parsed.port or
            parsed.query or parsed.fragment or '%' in parsed.path):
        raise BuildError('Enter a GitHub repository URL: https://github.com/owner/repository '
                         '(a /tree/branch link also works)')
    path=parsed.path.strip('/')
    components=path.split('/')
    if len(components) < 2:
        raise BuildError('Enter the GitHub repository URL including owner and repository')
    owner,repo=components[:2]
    if not re.fullmatch(r'[A-Za-z0-9-]+',owner) or owner.startswith('-') or \
       not re.fullmatch(r'[A-Za-z0-9_.-]+',repo) or repo.startswith('-'):
        raise BuildError('Invalid GitHub repository URL')
    if repo.endswith('.git'):repo=repo[:-4]
    if not repo or repo in ('.','..') or '..' in repo:
        raise BuildError('Invalid GitHub repository name')
    branch=None
    if len(components)>2:
        if len(components)<4 or components[2]!='tree':
            raise BuildError('Use a repository URL or its GitHub /tree/branch link')
        branch=validate_branch('/'.join(components[3:]))
    return f'https://github.com/{owner}/{repo}.git', f'{owner}/{repo}', branch


def validate_repo(value: str) -> tuple[str, str]:
    """Restrict clones to HTTPS GitHub repository URLs."""
    clone,slug,_=parse_repo_selection(value)
    return clone,slug


def validate_branch(name: str) -> str:
    s = name.strip()
    if not BRANCH_RE.fullmatch(s) or any(t in s for t in ('..','//','@{','\\')) or \
       s.endswith(('/', '.', '.lock')) or s.startswith(('-','/','.')):
        raise BuildError('Invalid Git branch name')
    for part in s.split('/'):
        if not part or part.startswith('.') or part.endswith('.') or part.endswith('.lock'):
            raise BuildError('Invalid branch component')
    return s


def validate_package_id(pkg: str) -> str:
    if not PKG_RE.fullmatch(pkg) or len(pkg) > 200:
        raise BuildError('Invalid Android application ID')
    return pkg


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_id(value: str) -> str:
    validate_package_id(value)
    return value.lower()


def safe_tag(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]', '-', value)[:55].strip('.-') or 'release'


def vault_root() -> Path:
    base = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else os.environ.get('XDG_DATA_HOME')
    return Path(base) / 'PMS-Apk-Builder' if base else Path.home()/'.local/share/PMS-Apk-Builder'


def tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise BuildError(f'Missing tool: {name}. Install the Android project toolchain and retry.')
    return found


def run(args: list[str], *, cwd: Path | None = None, env: dict | None = None,
        log=None, capture=False, timeout=None) -> str:
    """Never pass commands via a shell; do not log inherited environment."""
    if log:
        log('Running: ' + ' '.join(Path(a).name if i == 0 else a for i,a in enumerate(args))
            if not any('pass' in str(a).lower() for a in args) else 'Running secure signing tool')
    try:
        result = subprocess.run(args, cwd=cwd, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False, errors='replace')
    except (OSError, subprocess.TimeoutExpired) as e:
        raise BuildError(f'Command could not complete: {Path(args[0]).name} ({type(e).__name__})') from e
    if log and result.stdout:
        # Passwords live only in process env. Never print the signing env or key material.
        for line in result.stdout.splitlines():
            log(line[:1500])
    if result.returncode:
        raise BuildError(f'{Path(args[0]).name} failed (exit {result.returncode}); no APK declared verified')
    return result.stdout if capture else ''


def dpapi_encrypt(data: bytes) -> bytes:
    if os.name != 'nt':
        raise BuildError('Local signing vault requires Windows DPAPI. Use the Windows EXE.')
    class Blob(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]
    raw = ctypes.create_string_buffer(data)
    in_blob = Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_byte)))
    out_blob = Blob()
    crypt = ctypes.windll.crypt32
    if not crypt.CryptProtectData(ctypes.byref(in_blob), 'PMS APK signing', None, None,
                                  None, 0, ctypes.byref(out_blob)):
        raise BuildError('Windows DPAPI could not encrypt the signing password')
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def dpapi_decrypt(blob: bytes) -> bytes:
    if os.name != 'nt':
        raise BuildError('Local signing vault requires Windows DPAPI. Use the Windows EXE.')
    class Blob(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]
    raw = ctypes.create_string_buffer(blob)
    in_blob = Blob(len(blob), ctypes.cast(raw, ctypes.POINTER(ctypes.c_byte)))
    out_blob = Blob()
    crypt = ctypes.windll.crypt32
    if not crypt.CryptUnprotectData(ctypes.byref(in_blob), None, None, None,
                                    None, 0, ctypes.byref(out_blob)):
        raise BuildError('Signing password cannot be unlocked by this Windows user; restore an encrypted backup')
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def keytool_certificate(keystore: Path, alias: str, password: str) -> str:
    env = os.environ.copy(); env['PMS_SIGNING_PASSWORD'] = password
    out = run([tool('keytool'), '-list', '-v', '-storetype', 'PKCS12',
               '-keystore', str(keystore), '-alias', alias,
               '-storepass:env', 'PMS_SIGNING_PASSWORD'], env=env, capture=True)
    m = re.search(r'SHA256:\s*([0-9A-Fa-f:]{64,95})', out)
    if not m:
        raise BuildError('Cannot obtain certificate SHA-256 from keystore')
    digest = m.group(1).replace(':','').lower()
    if not re.fullmatch(r'[a-f0-9]{64}',digest):
        raise BuildError('Invalid signer certificate SHA-256')
    return digest


@dataclass
class Identity:
    package: str
    alias: str
    fingerprint: str
    keystore: Path
    password: str


class SigningVault:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else vault_root()/ 'signing'

    def location(self, package: str) -> Path:
        return self.root / canonical_id(package)

    def list_packages(self) -> list[str]:
        if not self.root.is_dir(): return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and (p/'identity.json').exists())

    def load(self, package: str) -> Identity | None:
        return self._load_at(self.location(package),package)

    def load_for_certificate(self, package: str, expected_sha256: str) -> Identity | None:
        """Choose an existing verified identity by cert, preserving other variants."""
        if not re.fullmatch(r'[a-f0-9]{64}', expected_sha256):
            raise BuildError('Invalid required signing certificate fingerprint')
        default=self.load(package)
        if default and default.fingerprint==expected_sha256:return default
        return self._load_at(self.root/'alternatives'/canonical_id(package)/expected_sha256,package,
                             required_fingerprint=expected_sha256)

    def _load_at(self,dirpath: Path,package:str,required_fingerprint:str|None=None) -> Identity | None:
        meta=dirpath/'identity.json'
        key=dirpath/'release.p12'
        secret=dirpath/'password.dpapi'
        if not dirpath.exists(): return None
        if not all(p.is_file() and not p.is_symlink() for p in (meta,key,secret)):
            raise BuildError('Partial or unsafe signing identity; refusing to generate another')
        cfg=json.loads(meta.read_text('utf8'))
        if cfg.get('format') != 1 or cfg.get('package') != canonical_id(package) or \
           cfg.get('alias') != 'pmsrelease' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',str(cfg.get('alias'))):
            raise BuildError('Invalid signing identity metadata')
        if sha256_file(key) != cfg.get('keystoreSha256'):
            raise BuildError('Keystore integrity mismatch; refusing to sign')
        password=dpapi_decrypt(secret.read_bytes()).decode('utf8')
        fp=keytool_certificate(key,cfg['alias'],password)
        if fp != cfg.get('fingerprint') or (required_fingerprint and fp!=required_fingerprint):
            raise BuildError('Signer fingerprint changed; refusing to sign')
        return Identity(cfg['package'],cfg['alias'],fp,key,password)

    def _save(self,package: str,alias: str,password: str,src: Path, *,
              expected_sha256:str|None=None) -> Identity:
        cert=keytool_certificate(src,alias,password)
        if expected_sha256 and cert!=expected_sha256:
            raise BuildError('Certificate mismatch: this key cannot sign the selected app profile')
        dest=self.location(package)
        if expected_sha256 and dest.exists():
            # Never overwrite a previously installed signer or its DPAPI secret.
            dest=self.root/'alternatives'/canonical_id(package)/expected_sha256
        if dest.exists():
            raise BuildError('Signing identity already exists; will not overwrite existing keys')
        dest.mkdir(parents=True, mode=0o700, exist_ok=False)
        try:
            (dest/'release.p12').write_bytes(src.read_bytes())
            (dest/'password.dpapi').write_bytes(dpapi_encrypt(password.encode('utf8')))
            meta={'format':1,'package':canonical_id(package),'alias':alias,
                  'fingerprint':cert,'keystoreSha256':sha256_file(dest/'release.p12'),
                  'createdUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
            (dest/'identity.json').write_text(json.dumps(meta,indent=2)+'\n','utf8')
            return Identity(canonical_id(package),alias,cert,dest/'release.p12',password)
        except Exception:
            # Only own newly-created identity directory, never remove pre-existing material.
            shutil.rmtree(dest,ignore_errors=True)
            raise

    def create(self, package: str, *, confirm=False) -> Identity:
        validate_package_id(package)
        if not confirm:
            raise BuildError('Explicit first-time signing-key approval required')
        if self.location(package).exists():
            raise BuildError('Existing signing identity present. Automatic replacement forbidden.')
        password=secrets.token_urlsafe(42)
        env=os.environ.copy();env['PMS_SIGNING_PASSWORD']=password
        with tempfile.TemporaryDirectory(prefix='pms-signing-') as tmp:
            target=Path(tmp)/'release.p12'
            run([tool('keytool'), '-genkeypair','-v','-storetype','PKCS12',
                 '-keystore',str(target),'-alias','pmsrelease','-keyalg','RSA',
                 '-keysize','3072','-sigalg','SHA256withRSA','-validity','9125',
                 '-dname','CN=APK Release, OU=PMS Builder, O=Local Owner, C=US',
                 '-storepass:env','PMS_SIGNING_PASSWORD',
                 '-keypass:env','PMS_SIGNING_PASSWORD','-noprompt'],env=env)
            return self._save(package,'pmsrelease',password,target)

    def import_existing(self, package: str, keystore: Path, alias: str,
                        password: str, key_password: str | None = None, *,
                        expected_sha256: str | None = None) -> Identity:
        """Import a user-approved ORIGINAL JKS or PKCS12, never guess passwords.

        JKS key passwords may differ from store passwords. Preserve the original
        signing certificate while converting to the local encrypted PKCS12 vault.
        """
        validate_package_id(package)
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',alias):
            raise BuildError('Invalid keystore alias')
        keystore=Path(keystore)
        if not keystore.is_file() or _unsafe_reparse(keystore) or keystore.stat().st_size>20*1024*1024:
            raise BuildError('Existing signing keystore not found or unsafe')
        if expected_sha256 and not re.fullmatch(r'[a-f0-9]{64}', expected_sha256):
            raise BuildError('Invalid required signing certificate fingerprint')
        if expected_sha256:
            if self.load_for_certificate(package,expected_sha256):
                raise BuildError('This verified signer is already saved for the selected app')
        elif self.location(package).exists():
            raise BuildError('Signing identity already exists; will not overwrite existing keys')
        with tempfile.TemporaryDirectory(prefix='pms-import-') as tmp:
            target=Path(tmp)/'import.p12'
            # JKS has a distinctive file signature; extensions are not reliable.
            with keystore.open('rb') as input_file:
                is_jks=input_file.read(4)==b'\xfe\xed\xfe\xed'
            if is_jks:
                env=os.environ.copy()
                env['PMS_ORIGINAL_STORE_PASSWORD']=password
                env['PMS_ORIGINAL_KEY_PASSWORD']=key_password if key_password else password
                newpassword=secrets.token_urlsafe(42)
                env['PMS_NEW_SIGNING_PASSWORD']=newpassword
                run([tool('keytool'),'-importkeystore',
                    '-srckeystore',str(keystore),'-srcstoretype','JKS',
                    '-srcstorepass:env','PMS_ORIGINAL_STORE_PASSWORD',
                    '-srcalias',alias,'-srckeypass:env','PMS_ORIGINAL_KEY_PASSWORD',
                    '-destkeystore',str(target),'-deststoretype','PKCS12',
                    '-deststorepass:env','PMS_NEW_SIGNING_PASSWORD',
                    '-destkeypass:env','PMS_NEW_SIGNING_PASSWORD',
                    '-destalias',alias,'-noprompt'],env=env)
                return self._save(package,alias,newpassword,target,expected_sha256=expected_sha256)
            env=os.environ.copy();env['PMS_SIGNING_PASSWORD']=password
            run([tool('keytool'),'-list','-storetype','PKCS12','-keystore',str(keystore),
                 '-alias',alias,'-storepass:env','PMS_SIGNING_PASSWORD'],env=env)
            shutil.copyfile(keystore,target)
            return self._save(package,alias,password,target,expected_sha256=expected_sha256)

    def backup(self, package: str, destination: Path, passphrase: str):
        if len(passphrase) < 12:
            raise BuildError('Encrypted-backup passphrase must be at least 12 characters')
        ident=self.load(package)
        if ident is None:
            raise BuildError('No signing key saved for this app')
        if destination.exists():
            raise BuildError('Refusing to overwrite an existing backup')
        payload=json.dumps({'format':1,'package':ident.package,'alias':ident.alias,
          'fingerprint':ident.fingerprint,'password':ident.password,
          'keystore':base64.b64encode(ident.keystore.read_bytes()).decode('ascii')}).encode('utf8')
        salt=os.urandom(16);nonce=os.urandom(12)
        key=hashlib.scrypt(passphrase.encode('utf8'),salt=salt,n=2**15,r=8,p=1,dklen=32,maxmem=128*1024*1024)
        cipher=AESGCM(key).encrypt(nonce,payload,BACKUP_AAD)
        wrapper={'format':1,'kind':'PMS-APK-SIGNING-BACKUP','salt':base64.b64encode(salt).decode(),
                 'nonce':base64.b64encode(nonce).decode(),'data':base64.b64encode(cipher).decode()}
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x',encoding='utf8') as f:json.dump(wrapper,f)

    def restore(self, file: Path, passphrase: str) -> Identity:
        if not file.is_file() or file.stat().st_size > 20*1024*1024:
            raise BuildError('Invalid or oversized encrypted signing backup')
        cfg=json.loads(file.read_text('utf8'))
        if cfg.get('kind')!='PMS-APK-SIGNING-BACKUP' or cfg.get('format')!=1:
            raise BuildError('Unknown signing backup format')
        try:
            salt=base64.b64decode(cfg['salt'],validate=True)
            nonce=base64.b64decode(cfg['nonce'],validate=True)
            body=base64.b64decode(cfg['data'],validate=True)
            if len(salt)!=16 or len(nonce)!=12:raise ValueError('invalid salt/nonce')
            key=hashlib.scrypt(passphrase.encode('utf8'),salt=salt,n=2**15,r=8,p=1,dklen=32,maxmem=128*1024*1024)
            payload=json.loads(AESGCM(key).decrypt(nonce,body,BACKUP_AAD))
            package=validate_package_id(payload['package'])
            if self.location(package).exists():
                raise BuildError('Signing identity already exists; will not overwrite it')
            src=base64.b64decode(payload['keystore'],validate=True)
            if len(src)>10*1024*1024:raise ValueError('keystore too big')
            with tempfile.TemporaryDirectory(prefix='pms-restore-') as td:
                path=Path(td)/'restore.p12';path.write_bytes(src)
                ident=self._save(package,payload['alias'],payload['password'],path)
            if ident.fingerprint!=payload['fingerprint']:
                shutil.rmtree(self.location(package),ignore_errors=True)
                raise BuildError('Restored signing fingerprint does not match backup')
            return ident
        except BuildError:
            raise
        except (ValueError,KeyError,TypeError,UnicodeError) as e:
            raise BuildError('Backup decryption failed or backup was modified') from e
        except Exception as e:
            raise BuildError('Backup decryption failed or backup was modified') from e


def sdk_candidates(configured: str | Path | None = None) -> list[Path]:
    """Locate Android SDK installations without touching installed tools.

    A user-selected SDK directory wins; otherwise follow official environment
    settings and the normal Android Studio paths for Windows and other OSes.
    """
    if configured and str(configured).strip():
        return [Path(str(configured).strip().strip('"')).expanduser()]
    home=Path.home()
    values=[os.environ.get('PMS_ANDROID_SDK_ROOT'),os.environ.get('ANDROID_SDK_ROOT'),
            os.environ.get('ANDROID_HOME')]
    local=os.environ.get('LOCALAPPDATA')
    if local:values.append(str(Path(local)/'Android'/'Sdk'))
    profile=os.environ.get('USERPROFILE')
    if profile:values.append(str(Path(profile)/'AppData'/'Local'/'Android'/'Sdk'))
    values.extend([str(home/'AppData'/'Local'/'Android'/'Sdk'),
                   str(home/'Android'/'Sdk'),str(home/'Android'/'sdk'),
                   str(home/'Library'/'Android'/'sdk')])
    roots=[];seen=set()
    for raw in values:
        if not raw:continue
        path=Path(raw.strip().strip('"')).expanduser()
        key=os.path.normcase(str(path))
        if key not in seen:roots.append(path);seen.add(key)
    return roots


def sdk_tool_paths(directory: Path, *, windows: bool | None = None) -> dict[str,Path]:
    """Resolve platform-specific build-tool names, especially apksigner.bat.

    A complete *single* SDK version must supply all 3 executables; never mix
    tools from separate versions or directories.
    """
    if windows is None:windows=os.name=='nt'
    def choose(stem: str) -> Path:
        suffixes=('.bat','.exe') if stem=='apksigner' and windows else \
                 ('.exe',) if windows else ('',)
        for suffix in suffixes:
            candidate=directory/(stem+suffix)
            if candidate.is_file():return candidate
        return directory/(stem+suffixes[0])
    return {stem:choose(stem) for stem in ('aapt','zipalign','apksigner')}


def sdk_build_tools(configured: str | Path | None = None, *, windows: bool | None = None) -> dict[str,Path]:
    """Discover a complete SDK Build Tools release; read-only and fail-closed."""
    roots=sdk_candidates(configured)
    for root in roots:
        build=root/'build-tools'
        if not build.is_dir():continue
        versions=sorted((x for x in build.iterdir() if x.is_dir()),
            key=lambda x: (not bool(re.search(r'(?:alpha|beta|rc)',x.name,re.I)),
                           tuple(int(y) for y in re.findall(r'\d+',x.name))),reverse=True)
        for version in versions:
            found=sdk_tool_paths(version, windows=windows)
            if all(file.is_file() for file in found.values()):return found
    searched=', '.join(str(x) for x in roots[:5]) or '(no SDK paths)'
    raise BuildError('Android SDK Build Tools not found or incomplete. '
                     'On Windows the required files are aapt.exe, zipalign.exe and '
                     'apksigner.bat. Select your Android SDK folder in the builder '
                     '(not the build-tools/version folder), or install Build Tools '
                     'using Android Studio > SDK Manager. Searched: '+searched)


# Discovery never opens the private key content, guesses passwords or imports keys.
# The user must explicitly choose a matching original signing identity.
KEY_SUFFIXES=frozenset(('.jks','.keystore','.p12','.pfx','.pkcs12'))
KEY_SKIP_DIRS=frozenset(('node_modules','.git','.hg','.svn','.gradle','.venv','venv',
  '.cache','__pycache__','build','dist','.next','temp','tmp','windows','program files',
  'program files (x86)','sdk','gradle','android sdk','system volume information'))


@dataclass(frozen=True)
class KeyCandidate:
    path: Path
    size_bytes: int


@dataclass(frozen=True)
class KeySearchResult:
    candidates: tuple[KeyCandidate, ...]
    visited_entries: int
    limited: bool


def default_key_search_roots(home: Path | None = None) -> list[Path]:
    """Find likely *current-user* key locations; never scan other user profiles."""
    home=Path(home) if home is not None else Path.home()
    roots=[home,home/'Documents',home/'Downloads',home/'Desktop',home/'.android',
           home/'AppData'/'Local'/'Printmarks',home/'AppData'/'Roaming'/'Printmarks']
    try:
        roots.extend(p for p in home.iterdir() if p.is_dir() and p.name.lower().startswith('onedrive'))
    except (OSError,PermissionError):pass
    return roots


def _unsafe_reparse(path: Path) -> bool:
    """Avoid following shortcuts, symlinks, Windows junctions, or reparse points."""
    try:
        if path.is_symlink() or getattr(path,'is_junction',lambda:False)():return True
        info=path.stat(follow_symlinks=False)
        return bool(getattr(info,'st_file_attributes',0) & 0x400)
    except (OSError,PermissionError):return True


def discover_signing_keys(folders: list[Path] | None = None, *,
                         max_depth: int = 6, max_entries: int = 50000,
                         max_results: int = 200) -> KeySearchResult:
    """Bounded, read-only candidate scan; no password prompts or key content reads.

    Default folders cover the current Windows user and common private-app folders.
    A separate user-chosen folder/drive can be supplied for unusual locations.
    """
    if max_depth<0 or max_entries<1 or max_results<1:
        raise BuildError('Invalid signing-key search limits')
    roots=default_key_search_roots() if folders is None else [Path(x) for x in folders]
    seen_dirs={};seen_files=set();matches=[];count=0;limited=False
    for initial in roots:
        base=Path(initial).expanduser()
        if not base.is_dir() or _unsafe_reparse(base):continue
        # A shallow home scan avoids AppData/SDK caches; dedicated roots below
        # search Documents, Downloads, and Printmarks more deeply.
        depth_limit=min(max_depth,2) if folders is None and base==Path.home() else max_depth
        stack=[(base,0)]
        while stack:
            directory,depth=stack.pop()
            signature=os.path.normcase(os.path.abspath(directory))
            remaining=depth_limit-depth
            if seen_dirs.get(signature,-1)>=remaining:continue
            seen_dirs[signature]=remaining
            try:
                with os.scandir(directory) as scan:
                    entries=sorted(scan,key=lambda x:x.name.lower())
            except (OSError,PermissionError):continue
            for entry in entries:
                count+=1
                if count>max_entries:
                    limited=True;break
                p=Path(entry.path)
                if _unsafe_reparse(p):continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if depth<depth_limit and entry.name.lower() not in KEY_SKIP_DIRS:
                            stack.append((p,depth+1))
                    elif entry.is_file(follow_symlinks=False) and p.suffix.lower() in KEY_SUFFIXES:
                        filekey=os.path.normcase(os.path.abspath(p))
                        if filekey in seen_files:continue
                        seen_files.add(filekey)
                        size=entry.stat(follow_symlinks=False).st_size
                        if 0<size<=20*1024*1024:
                            matches.append(KeyCandidate(p,size))
                            if len(matches)>=max_results:
                                limited=True;break
                except (OSError,PermissionError):continue
            if limited:break
        if limited:break
    matches.sort(key=lambda x:str(x.path).lower())
    return KeySearchResult(tuple(matches),count,limited)


def configure_gradle_sdk(gradle_dir: Path, sdk_root: Path) -> None:
    """Write local.properties only inside the disposable checked-out project."""
    gradle_dir=Path(gradle_dir)
    sdk_root=Path(sdk_root)
    if not gradle_dir.is_dir() or not (sdk_root/'build-tools').is_dir():
        raise BuildError('Gradle project or Android SDK root is missing')
    props=gradle_dir/'local.properties'
    if props.is_symlink() or getattr(props,'is_junction',lambda:False)():
        raise BuildError('Unsafe Gradle local.properties link')
    try:
        old=props.read_text('utf8') if props.exists() else ''
    except UnicodeError as e:
        raise BuildError('Cannot decode Gradle local.properties') from e
    lines=[line for line in old.splitlines() if not re.match(r'^\s*sdk\.dir\s*[:=]',line)]
    lines.append('sdk.dir='+sdk_root.as_posix())
    props.write_text('\n'.join(lines)+'\n',encoding='utf8')

def apk_package(apk: Path, sdk: dict[str,Path]) -> str:
    out=run([str(sdk['aapt']),'dump','badging',str(apk)],capture=True)
    m=re.search(r"^package:\s+name='([^']+)'",out,re.M)
    if not m:
        raise BuildError('APK package ID could not be read; refusing to sign')
    return validate_package_id(m.group(1))



def source_package_hint(root: Path, project_type: str) -> str | None:
    """Detect only a literal, unambiguous application ID without executing source code.

    This is a *pre-build convenience*, never a substitute for reading the
    actual compiled APK ID. Projects with product flavors/dynamic IDs are
    deliberately deferred until post-build verification.
    """
    root=Path(root)
    if project_type=='capacitor':
        config=root/'capacitor.config.json'
        if config.is_file() and config.stat().st_size<=256*1024:
            try:
                value=json.loads(config.read_text('utf8')).get('appId')
                return validate_package_id(value) if isinstance(value,str) else None
            except (ValueError,UnicodeError,TypeError,BuildError):return None
        config=root/'capacitor.config.ts'
        if config.is_file() and config.stat().st_size<=256*1024:
            try:text=config.read_text('utf8')
            except UnicodeError:return None
            # Supports common Capacitor literal config. Never evaluate JS/TS.
            matches=re.findall(r"""\bappId\s*:\s*(['"])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\1""",text)
            if len(matches)==1:
                try:return validate_package_id(matches[0][1])
                except BuildError:return None
        return None
    if project_type not in ('flutter','gradle','gradle-android'):
        return None
    folder=root if project_type=='gradle' else root/'android'
    for filename in ('app/build.gradle','app/build.gradle.kts'):
        config=folder/filename
        if not config.is_file() or config.stat().st_size>256*1024:continue
        try:text=config.read_text('utf8')
        except UnicodeError:continue
        # Product flavors or suffixes may change application ID dynamically.
        if re.search(r'\b(productFlavors|applicationIdSuffix)\b',text):return None
        matches=re.findall(r"""\bapplicationId\s*(?:=\s*)?(['"])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\1""",text)
        if len(matches)==1:
            try:return validate_package_id(matches[0][1])
            except BuildError:return None
    return None


def preflight_signer(source: Path, project_type: str, vault: SigningVault, *,
                     expected_package: str | None = None, allow_new_key=False,
                     log=None) -> str | None:
    """Reject a missing signer before expensive builds when the ID is known."""
    if expected_package:
        expected_package=validate_package_id(expected_package)
    inferred=source_package_hint(source,project_type)
    if inferred and expected_package and inferred.lower()!=expected_package.lower():
        raise BuildError('Selected package ID '+expected_package+' does not match source application ID '+
                         inferred+'. Check the intended Customer/Developer variant before building.')
    candidate=inferred or expected_package
    if candidate and not allow_new_key:
        signer=vault.load(candidate)
        if signer is None:
            raise BuildError('Signing preflight: no saved signer for '+candidate+
                '. Build stopped BEFORE npm/Gradle. Use Find signing keys, import the ORIGINAL key, '+
                'and compare it with your previous signed APK. Do not create a replacement signer for updates.')
        if log:log('Signing preflight: saved signer found for '+candidate+'; final APK identity will still be verified.')
    elif not candidate and not allow_new_key and log:
        log('Signing preflight: dynamic/unknown package ID. APK will be checked for a saved signer after compilation.')
    return candidate


def verify_signer_against_original_apk(apk: Path, package: str, vault: SigningVault, *,
                                        sdk: dict[str,Path] | None = None,
                                        expected_sha256:str|None=None) -> str:
    """Compare a saved local signer with a *previously signed* APK, read-only."""
    package=validate_package_id(package)
    apk=Path(apk)
    if not apk.is_file() or apk.is_symlink():
        raise BuildError('Select an existing, regular signed APK file for comparison')
    sdk=sdk or sdk_build_tools()
    if apk_package(apk,sdk).lower()!=package.lower():
        raise BuildError('Old APK package does not match the selected signing identity; refusing comparison')
    out=run([str(sdk['apksigner']),'verify','--verbose','--print-certs',str(apk)],capture=True)
    hashes=re.findall(r'Signer #\d+ certificate SHA-256 digest:\s*([a-fA-F0-9]{64})',out)
    if len(hashes)!=1:
        raise BuildError('Old APK signer could not be uniquely verified')
    current=release_identity(vault,package,expected_sha256)
    if current is None:
        raise BuildError('Import the original signing keystore before comparing APK signatures')
    if hashes[0].lower()!=current.fingerprint:
        raise BuildError('SIGNER MISMATCH: saved key does NOT match the old signed APK. Do not build an update with this key.')
    return current.fingerprint


def detect_project(root: Path, forced: str='auto') -> str:
    types=[]
    if (root/'pubspec.yaml').is_file() and (root/'android').is_dir():types.append('flutter')
    if ((root/'capacitor.config.ts').is_file() or (root/'capacitor.config.json').is_file()) and \
       (root/'package.json').is_file():types.append('capacitor')
    if ((root/'gradlew.bat').is_file() or (root/'gradlew').is_file()) and \
       ((root/'app').is_dir() or (root/'settings.gradle').is_file() or (root/'settings.gradle.kts').is_file()):types.append('gradle')
    if (root/'android'/'gradlew.bat').is_file() or (root/'android'/'gradlew').is_file():types.append('gradle-android')
    if forced!='auto':
        if forced not in types:raise BuildError(f'Project is not a supported {forced} repository')
        return forced
    for choice in ('flutter','capacitor','gradle-android','gradle'):
        if choice in types:return choice
    raise BuildError('No supported Android project found (Flutter, Capacitor or Gradle Android)')


def choose_apk(root:Path) ->Path:
    candidates=[p for p in root.rglob('*.apk') if p.is_file() and ('release' in p.name.lower() or 'release' in '/'.join(p.parts[-5:]).lower())
                and ('outputs' in p.parts or 'flutter-apk' in p.parts)
                and 'test' not in p.name.lower() and not p.name.lower().endswith('-androidtest.apk')]
    # Flutter may create both a wrapper APK and an identical Gradle intermediate.
    flutter=[p for p in candidates if 'flutter-apk' in p.parts]
    if flutter:candidates=flutter
    uniq={p.resolve() for p in candidates}
    if len(uniq)!=1:
        raise BuildError(f'Expected exactly one release APK, found {len(uniq)}. Choose a single app/variant before building.')
    return next(iter(uniq))


def build_source(root:Path, project_type:str, log=None, env=None, sdk_root=None, recipe=None, recipe_step_env=None):
    if project_type=='flutter':
        run([tool('flutter'),'pub','get'],cwd=root,log=log,env=env)
        run([tool('flutter'),'build','apk','--release'],cwd=root,log=log,env=env)
    elif project_type=='capacitor':
        if not (root/'package-lock.json').is_file():
            raise BuildError('Capacitor requires package-lock.json for reproducible npm ci')
        run([tool('npm.cmd' if os.name=='nt' else 'npm'),'ci'],cwd=root,log=log,env=env)
        data=json.loads((root/'package.json').read_text('utf8'))
        if 'build' not in data.get('scripts',{}):
            raise BuildError('Capacitor project must define an npm build script')
        run([tool('npm.cmd' if os.name=='nt' else 'npm'),'run','build'],cwd=root,log=log,env=env)
        if recipe:run_recipe_stage(recipe,'beforeSync',root,recipe_step_env or env,tool,run,log=log)
        npx=tool('npx.cmd' if os.name=='nt' else 'npx')
        if not (root/'android').is_dir():
            run([npx,'--no-install','cap','add','android'],cwd=root,log=log,env=env)
        run([npx,'--no-install','cap','sync','android'],cwd=root,log=log,env=env)
        if recipe:run_recipe_stage(recipe,'afterSync',root,recipe_step_env or env,tool,run,log=log)
        return build_source(root,'gradle-android',log=log,env=env,sdk_root=sdk_root,recipe=recipe,recipe_step_env=recipe_step_env)
    elif project_type in ('gradle','gradle-android'):
        gradle_dir=root/'android' if project_type=='gradle-android' else root
        wrapper=gradle_dir/('gradlew.bat' if os.name=='nt' else 'gradlew')
        if not wrapper.is_file():raise BuildError('Gradle wrapper missing')
        if sdk_root is not None:configure_gradle_sdk(gradle_dir,Path(sdk_root))
        if recipe:run_recipe_stage(recipe,'beforeGradle',root,recipe_step_env or env,tool,run,log=log)
        if os.name!='nt':wrapper.chmod(wrapper.stat().st_mode|0o111)
        run([str(wrapper),'assembleRelease','--no-daemon','--console=plain'],cwd=gradle_dir,log=log,env=env)
    else:
        raise BuildError('Unsupported project type')


def signed_apk(source_apk:Path, package:str, identity:Identity, dest:Path, sdk:dict[str,Path],log=None):
    if canonical_id(package)!=identity.package:
        raise BuildError('APK package does not match the signing identity')
    if dest.exists():raise BuildError('Destination APK already exists; refusing overwrite')
    dest.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pms-sign-apk-') as td:
        aligned=Path(td)/'aligned.apk'
        staging=Path(td)/'signed.apk'
        run([str(sdk['zipalign']),'-f','-p','4',str(source_apk),str(aligned)],log=log)
        env=os.environ.copy();env['PMS_SIGNING_PASSWORD']=identity.password
        run([str(sdk['apksigner']),'sign','--ks',str(identity.keystore),
             '--ks-key-alias',identity.alias,'--ks-pass','env:PMS_SIGNING_PASSWORD',
             '--key-pass','env:PMS_SIGNING_PASSWORD','--out',str(staging),str(aligned)],env=env,log=log)
        checked=run([str(sdk['apksigner']),'verify','--verbose','--print-certs',str(staging)],capture=True)
        fps=re.findall(r'Signer #\d+ certificate SHA-256 digest:\s*([a-fA-F0-9]+)',checked)
        if len(fps)!=1 or fps[0].lower()!=identity.fingerprint:
            raise BuildError('APK signer certificate verification failed; refusing output')
        if apk_package(staging,sdk)!=package:
            raise BuildError('APK package changed during signing')
        shutil.copyfile(staging,dest)
    return sha256_file(dest)


def clone_branch(repo:str,branch:str,working:Path,log=None) -> str:
    url,_=validate_repo(repo);branch=validate_branch(branch)
    if working.exists():raise BuildError('Temporary checkout path already exists')
    run([tool('git'),'-c','protocol.file.allow=never','clone','--no-checkout','--depth','1',
         '--single-branch','--branch',branch,url,str(working)],log=log)
    commit=run([tool('git'),'rev-parse','HEAD'],cwd=working,capture=True).strip()
    if not HEX40.fullmatch(commit):raise BuildError('Cannot verify cloned commit ID')
    run([tool('git'),'checkout','--detach',commit],cwd=working,log=log)
    return commit


def remote_branches(repo:str)->list[str]:
    url,_=validate_repo(repo)
    out=run([tool('git'),'ls-remote','--heads',url],capture=True)
    names=[]
    for line in out.splitlines():
        match=re.fullmatch(r'[a-f0-9]{40}\s+refs/heads/(.+)',line)
        if match:
            try:names.append(validate_branch(match.group(1)))
            except BuildError:pass
    return sorted(names)


def release_identity(vault,package:str,expected_sha256:str|None):
    # Older extensions/test vaults can implement only load(); a pinned
    # fingerprint is still checked by the release preflight below.
    if expected_sha256 and hasattr(vault,'load_for_certificate'):
        return vault.load_for_certificate(package,expected_sha256)
    return vault.load(package)


def create_release(repo:str,branch:str,output:Path,vault:SigningVault, *,
                   project_type='auto',allow_new_key=False,log=None, sdk_root=None,
                   expected_package: str | None = None, recipe_profile: str = 'auto',
                   recipe_file: Path | None = None) -> dict:
    repo_url,repo_name=validate_repo(repo);branch=validate_branch(branch)
    sdk=sdk_build_tools(sdk_root)
    if log:log('Android SDK Build Tools found at: '+str(sdk['aapt'].parent))
    with tempfile.TemporaryDirectory(prefix='pms-android-build-') as work:
        src=Path(work)/'source'
        sha=clone_branch(repo_url,branch,src,log=log)
        try:recipe=load_recipe(src,recipe_profile,external_file=recipe_file)
        except RecipeError as exc:raise BuildError(str(exc)) from exc
        kind=detect_project(src,project_type)
        if recipe and recipe.project_type!=kind:
            raise BuildError('Recipe project type does not match detected Android project')
        if recipe and expected_package and expected_package.lower()!=recipe.package.lower():
            raise BuildError('Requested package does not match selected recipe profile')
        if recipe_file and log:log('Using user-selected local build recipe (never committed to source).')
        if log:log(f'Project type: {kind} | source: {sha[:12]}' +
                   (f' | native recipe: {recipe.profile}' if recipe else ' | generic build'))
        if recipe:
            identity=release_identity(vault,recipe.package,recipe.signer_sha256)
            if not identity and recipe.signer_sha256:
                raise BuildError('Recipe requires ORIGINAL signing certificate for '+recipe.package+
                    '. Import its matching keystore. New-key generation is forbidden.')
            if identity and recipe.signer_sha256 and identity.fingerprint!=recipe.signer_sha256:
                raise BuildError('SIGNER MISMATCH: saved signer for '+recipe.package+
                    ' does not match the original certificate required by this release recipe. '
                    'Do not publish an update using a different signing key.')
            if not identity and not allow_new_key:
                raise BuildError('No signer imported for recipe package '+recipe.package)
        else:
            preflight_signer(src,kind,vault,expected_package=expected_package,
                             allow_new_key=allow_new_key,log=log)
        # Only expose per-repository secrets to this repository's build commands,
        # not to clone/git or unrelated projects. Build scripts are trusted code.
        saved=SecretVault().values(repo_url)
        build_env=os.environ.copy();build_env.update(saved)
        # The detected build-tools directory alone is insufficient for Gradle:
        # explicitly advertise the SDK root to the entire build chain.
        selected_sdk=sdk['aapt'].parent.parent.parent
        build_env['ANDROID_HOME']=str(selected_sdk)
        build_env['ANDROID_SDK_ROOT']=str(selected_sdk)
        recipe_step_env=None
        if recipe:
            build_env['CM_BRANCH']=branch
            build_env['CM_COMMIT']=sha
            build_env['CM_REPO_SLUG']=repo_name
            identity=release_identity(vault,recipe.package,recipe.signer_sha256)
            signing={}
            if identity:
                signing={'CM_KEYSTORE_PATH':str(identity.keystore),
                         'CM_KEYSTORE_PASSWORD':identity.password,
                         'CM_KEY_PASSWORD':identity.password,
                         'CM_KEY_ALIAS':identity.alias,
                         'KARAOKEY_SIGNING_CERT_SHA256':identity.fingerprint}
            try:recipe_step_env=recipe_env(recipe,build_env,signing,source_root=src)
            except RecipeError as exc:raise BuildError(str(exc)) from exc
        def sanitized_log(message):
            line=str(message)
            for value in list(saved.values())+([identity.password] if recipe and identity else []):
                if value:line=line.replace(value,'[REDACTED]')
            if log:log(line)
        build_kwargs={'log':sanitized_log,'env':build_env,'sdk_root':selected_sdk}
        if recipe:
            build_kwargs['recipe']=recipe
            build_kwargs['recipe_step_env']=recipe_step_env
        build_source(src,kind,**build_kwargs)
        apk=choose_apk(src)
        pkg=apk_package(apk,sdk)
        if recipe and pkg.lower()!=recipe.package.lower():
            raise BuildError('Recipe profile produced wrong Android package '+pkg+'; expected '+recipe.package)
        if expected_package and pkg.lower()!=expected_package.lower():
            raise BuildError('Compiled APK package '+pkg+' differs from selected package '+
                             expected_package+'. Do not sign the wrong app variant.')
        identity=release_identity(vault,pkg,recipe.signer_sha256 if recipe else None)
        if not identity:
            if not allow_new_key:
                raise BuildError('No signer found for '+pkg+'. Import original release keystore or explicitly authorize NEW signing identity (new installs only).')
            if log:log('First-time signing identity creation approved for '+pkg)
            identity=vault.create(pkg,confirm=True)
        # APK's package ID and signer's certificate are verified after signing.
        output=Path(output).expanduser().resolve()
        filename=f'{safe_tag(pkg)}-{safe_tag(branch)}-{sha[:12]}.apk'
        dest=output/filename
        digest=signed_apk(apk,pkg,identity,dest,sdk,log=log)
        try:
            if recipe:
                if dest.stat().st_size<recipe.min_apk_bytes:
                    raise BuildError('APK too small for required native release recipe: '+
                        str(dest.stat().st_size)+' bytes, minimum '+str(recipe.min_apk_bytes)+
                        '. Missing native features; refusing release.')
                run_recipe_stage(recipe,'afterSign',src,recipe_step_env,tool,run,apk=dest,log=sanitized_log)
                # Verification runs again in case a repository-owned post-sign step
                # touched the APK; signer/package identity must remain invariant.
                verify_signer_against_original_apk(dest,pkg,vault,sdk=sdk,
                    expected_sha256=recipe.signer_sha256)
                digest=sha256_file(dest)
        except Exception:
            dest.unlink(missing_ok=True)
            raise
        meta={'format':1,'repo':repo_name,'branch':branch,'sourceCommit':sha,
              'projectType':kind,'recipeProfile':recipe.profile if recipe else None,
              'package':pkg,'signerFingerprint':identity.fingerprint,
              'apk':filename,'sha256':digest,'createdUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
        manifest=dest.with_suffix('.manifest.json')
        if manifest.exists():
            dest.unlink(missing_ok=True)
            raise BuildError('Release manifest exists; refusing to overwrite')
        manifest.write_text(json.dumps(meta,indent=2)+'\n','utf8')
        if log:log('VERIFIED APK: '+str(dest)+' | SHA-256: '+digest)
        return meta


def publish_github_secrets(repo:str, package:str, vault:SigningVault, *, confirm:bool=False, log=None):
    """Explicit opt-in only. GitHub Actions secrets are WRITE-ONLY, never a recovery backup."""
    if not confirm:raise BuildError('Explicit GitHub Actions secrets upload approval required')
    _, name=validate_repo(repo)
    identity=vault.load(package)
    if not identity:raise BuildError('Signing identity missing')
    gh=tool('gh')
    # Do not pass secrets as CLI arguments or write plaintext temporary secret files.
    pairs={
        'PMS_SIGNING_P12_BASE64':base64.b64encode(identity.keystore.read_bytes()).decode('ascii'),
        'PMS_SIGNING_PASSWORD':identity.password,
        'PMS_SIGNING_ALIAS':identity.alias,
        'PMS_SIGNING_PACKAGE':identity.package,
        'PMS_SIGNING_CERT_SHA256':identity.fingerprint
    }
    for key,value in pairs.items():
        try:
            p=subprocess.run([gh,'secret','set',key,'--repo',name],input=value,
                             text=True,capture_output=True,timeout=90)
        except (OSError,subprocess.TimeoutExpired) as e:
            raise BuildError('GitHub CLI could not store Actions secret '+key) from e
        if p.returncode:
            raise BuildError('GitHub Actions secret upload failed for '+key+'; earlier secrets may already be set')
        if log:log('GitHub Actions secret updated: '+key+' (value never displayed)')
    if log:log('Note: GitHub Actions secrets are write-only, NOT a portable key backup. Export an encrypted backup separately.')


SECRET_NAME_RE = re.compile(r'^[A-Z][A-Z0-9_]{1,63}$')
# Prevent changing command resolution or replacing the signing protocol via env injection.
RESERVED_BUILD_ENV = frozenset({
    'PATH','PATHEXT','COMSPEC','SYSTEMROOT','WINDIR','TEMP','TMP','HOME','USERPROFILE',
    'LOCALAPPDATA','APPDATA','JAVA_HOME','ANDROID_HOME','ANDROID_SDK_ROOT',
    'PMS_SIGNING_PASSWORD','PMS_SIGNING_P12_BASE64','PMS_SIGNING_CERT_SHA256',
    'PYTHONPATH','PYTHONHOME','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS',
    'NODE_OPTIONS','GRADLE_OPTS','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS'
})


class SecretVault:
    """Optional per-repository encrypted build environment variables."""
    def __init__(self, root: Path | None = None):
        self.root=Path(root) if root else vault_root()/'build-secrets'

    def _file(self, repo: str) -> tuple[str,Path]:
        _,slug=validate_repo(repo)
        digest=hashlib.sha256(slug.lower().encode('utf8')).hexdigest()
        return slug,self.root/(digest+'.json')

    def _read(self,repo: str) -> dict:
        slug,filename=self._file(repo)
        if not filename.exists():return {'format':1,'repo':slug.lower(),'values':{}}
        if filename.is_symlink() or not filename.is_file():
            raise BuildError('Build secret vault must not be a symlink')
        cfg=json.loads(filename.read_text('utf8'))
        if cfg.get('format')!=1 or cfg.get('repo')!=slug.lower() or not isinstance(cfg.get('values'),dict):
            raise BuildError('Invalid repository secret vault')
        return cfg

    def names(self,repo: str)->list[str]:
        return sorted(self._read(repo)['values'])

    def set(self,repo: str,name: str,value: str,*,confirm=False)->None:
        if not confirm:raise BuildError('Explicit permission required to store build secret')
        if not SECRET_NAME_RE.fullmatch(name) or name in RESERVED_BUILD_ENV or name.startswith('PMS_'):
            raise BuildError('Invalid or reserved build environment variable name')
        if not value or len(value.encode('utf8'))>8192:
            raise BuildError('Secret value must be between 1 and 8192 bytes')
        cfg=self._read(repo)
        if name in cfg['values']:
            raise BuildError('This secret already exists. Delete it explicitly before replacing.')
        cfg['values'][name]=base64.b64encode(dpapi_encrypt(value.encode('utf8'))).decode('ascii')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        slug,path=self._file(repo)
        if path.exists() and path.is_symlink():raise BuildError('Unsafe secret file')
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf8',prefix='.pms-',suffix='.tmp',
                     dir=str(self.root),delete=False) as f:
            tmp=Path(f.name)
            json.dump(cfg,f,indent=2)
        try:tmp.replace(path)
        finally:tmp.unlink(missing_ok=True)

    def delete(self,repo: str,name: str,*,confirm=False):
        if not confirm:raise BuildError('Explicit deletion confirmation required')
        cfg=self._read(repo)
        if name not in cfg['values']:raise BuildError('Secret does not exist')
        del cfg['values'][name]
        _,path=self._file(repo)
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf8',prefix='.pms-',suffix='.tmp',
                     dir=str(self.root),delete=False) as f:
            tmp=Path(f.name);json.dump(cfg,f,indent=2)
        try:tmp.replace(path)
        finally:tmp.unlink(missing_ok=True)

    def values(self,repo: str)->dict[str,str]:
        cfg=self._read(repo);res={}
        for name,encoded in cfg['values'].items():
            if not SECRET_NAME_RE.fullmatch(name) or name in RESERVED_BUILD_ENV or name.startswith('PMS_'):
                raise BuildError('Unexpected secret name in saved vault')
            try:res[name]=dpapi_decrypt(base64.b64decode(encoded,validate=True)).decode('utf8')
            except (ValueError,UnicodeError) as e:raise BuildError('Cannot decrypt saved project build secret') from e
        return res

    def backup(self,repo:str,destination:Path,passphrase:str):
        if len(passphrase)<12:raise BuildError('Secret backup requires a strong passphrase (12+ characters)')
        if destination.exists():raise BuildError('Secret backup already exists; refusing overwrite')
        _,slug=validate_repo(repo)
        plaintext=json.dumps({'format':1,'repo':slug.lower(),'values':self.values(repo)}).encode('utf8')
        salt=os.urandom(16);nonce=os.urandom(12)
        key=hashlib.scrypt(passphrase.encode('utf8'),salt=salt,n=2**15,r=8,p=1,
                          dklen=32,maxmem=128*1024*1024)
        ciphertext=AESGCM(key).encrypt(nonce,plaintext,b'PMS-BUILD-ENV-BACKUP-V1')
        obj={'format':1,'kind':'PMS-APK-BUILD-SECRETS-BACKUP',
             'salt':base64.b64encode(salt).decode(), 'nonce':base64.b64encode(nonce).decode(),
             'data':base64.b64encode(ciphertext).decode()}
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('x',encoding='utf8') as f:json.dump(obj,f)

    def restore(self,file:Path,repo:str,passphrase:str):
        _,slug=validate_repo(repo)
        if not file.is_file() or file.stat().st_size>1024*1024:
            raise BuildError('Invalid build secrets backup')
        cfg=json.loads(file.read_text('utf8'))
        if cfg.get('kind')!='PMS-APK-BUILD-SECRETS-BACKUP' or cfg.get('format')!=1:
            raise BuildError('Wrong encrypted backup format')
        if self.names(repo):raise BuildError('Existing build secrets must not be overwritten')
        try:
            salt=base64.b64decode(cfg['salt'],validate=True)
            nonce=base64.b64decode(cfg['nonce'],validate=True)
            data=base64.b64decode(cfg['data'],validate=True)
            if len(salt)!=16 or len(nonce)!=12:raise ValueError('invalid params')
            key=hashlib.scrypt(passphrase.encode('utf8'),salt=salt,n=2**15,r=8,p=1,
                              dklen=32,maxmem=128*1024*1024)
            raw=json.loads(AESGCM(key).decrypt(nonce,data,b'PMS-BUILD-ENV-BACKUP-V1'))
            if raw.get('repo')!=slug.lower() or not isinstance(raw.get('values'),dict) or len(raw['values'])>100:
                raise ValueError('wrong repo or size')
            for k,v in raw['values'].items():
                if not SECRET_NAME_RE.fullmatch(k) or k in RESERVED_BUILD_ENV or k.startswith('PMS_') \
                        or not isinstance(v,str) or len(v.encode('utf8'))>8192 or not v:
                    raise ValueError('malformed secret')
            for k,v in raw['values'].items():self.set(repo,k,v,confirm=True)
        except (ValueError,KeyError,UnicodeError,TypeError) as e:
            raise BuildError('Cannot decrypt or validate build-secrets backup') from e
        except Exception as e:
            if isinstance(e,BuildError):raise
            raise BuildError('Cannot decrypt or validate build-secrets backup') from e


def publish_project_github_secrets(repo:str,vault:SecretVault,*,confirm=False,log=None):
    if not confirm:raise BuildError('Explicit GitHub Actions secrets upload approval required')
    _,slug=validate_repo(repo)
    saved=vault.values(repo)
    if not saved:raise BuildError('No project build secrets configured')
    gh=tool('gh')
    for name,value in saved.items():
        p=subprocess.run([gh,'secret','set',name,'--repo',slug],input=value,
                         text=True,capture_output=True,timeout=90)
        if p.returncode:raise BuildError('Could not set GitHub Actions secret '+name)
        if log:log('Stored GitHub Actions build secret: '+name+' (value hidden)')
