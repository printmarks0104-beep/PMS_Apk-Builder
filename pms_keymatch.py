"""Read-only discovery of local signing candidates for a selected Android release.

Private keys and passwords never leave this PC. JKS public certificates can be
indexed without unlocking a private key; an apparent match is provisional until
keytool authenticates the actual key during explicitly approved import.
"""
from __future__ import annotations

import hashlib
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CertificateHint:
    alias: str
    sha256: str


@dataclass(frozen=True)
class KeyMatch:
    path: Path
    alias: str | None
    certificate_sha256: str | None
    status: str  # 'certificate-candidate', 'requires-password'


@dataclass(frozen=True)
class MatchContext:
    repository: str
    branch: str
    package: str | None
    expected_certificate: str | None
    recipe_profile: str | None
    saved_signer_matches: bool
    matches: tuple[KeyMatch, ...]
    other_candidates: tuple[KeyMatch, ...]
    scan_limited: bool


def jks_public_certificates(path: Path) -> tuple[CertificateHint, ...]:
    """Parse only public certificate chains from a bounded JKS v1/v2 file.

    This does NOT verify JKS integrity: its private key remains encrypted.
    Always validate alias, password, private-key access, and fingerprint with
    keytool before importing or using a candidate for signing.
    """
    path=Path(path)
    if path.stat().st_size > 20*1024*1024 or path.is_symlink():
        return ()
    with path.open('rb') as stream:
        def read_exact(n):
            if n < 0 or n > 20*1024*1024:
                raise ValueError('Invalid JKS record')
            buf=stream.read(n)
            if len(buf)!=n:raise ValueError('Truncated JKS record')
            return buf
        def u16():return struct.unpack('>H',read_exact(2))[0]
        def u32():return struct.unpack('>I',read_exact(4))[0]
        def utf():
            n=u16()
            return read_exact(n).decode('utf-8','replace')
        if read_exact(4)!=b'\xfe\xed\xfe\xed':return ()
        version=u32()
        if version not in (1,2):return ()
        count=u32()
        if count>256:raise ValueError('JKS has too many records')
        hints=[]
        for _ in range(count):
            kind=u32()
            if kind not in (1,2):raise ValueError('Unsupported JKS entry')
            alias=utf();read_exact(8)  # timestamp
            if kind==1:
                n=u32();read_exact(n)  # encrypted private key: never decrypt
                cert_count=u32()
                if cert_count>32:raise ValueError('Oversized JKS chain')
                for index in range(cert_count):
                    if version==2:utf()  # certificate type
                    der=read_exact(u32())
                    if index==0 and alias and der:
                        hints.append(CertificateHint(alias,hashlib.sha256(der).hexdigest()))
            else:
                if version==2:utf()
                read_exact(u32())  # trusted cert, not a signing key: ignore
        return tuple(hints)


def match_candidates(candidates, expected_sha256: str | None):
    """Separate public-certificate candidates from password-required files."""
    matched=[];unknown=[]
    for item in candidates:
        path=item.path
        if path.suffix.lower()=='.jks' or path.suffix.lower()=='.keystore':
            try: certs=jks_public_certificates(path)
            except (OSError,ValueError,struct.error):certs=()
            for cert in certs:
                if expected_sha256 and cert.sha256==expected_sha256.lower():
                    matched.append(KeyMatch(path,cert.alias,cert.sha256,'certificate-candidate'))
            if certs and expected_sha256:
                # A valid JKS with nonmatching leaf certificates is definitively
                # not a match for the pinned signer, so it is not suggested.
                continue
        unknown.append(KeyMatch(path,None,None,'requires-password'))
    return tuple(matched),tuple(unknown)


def inspect_selected_branch(repo:str,branch:str, *, recipe_profile:str='auto',
                            recipe_file:Path|None=None,expected_package:str|None=None,
                            vault=None,folders=None,log=None):
    """Discover expected identity from the exact branch, then scan local keys.

    Cloning source does not execute source code. Never attempt passwords.
    The user must approve any import of the key that passes certificate checks.
    """
    import pms_core as core
    from pms_recipe import load_recipe, RecipeError
    core.validate_repo(repo);core.validate_branch(branch)
    vault=vault or core.SigningVault()
    with tempfile.TemporaryDirectory(prefix='pms-signing-preflight-') as tmp:
        root=Path(tmp)/'source'
        core.clone_branch(repo,branch,root,log=None)
        try:recipe=load_recipe(root,recipe_profile,external_file=recipe_file)
        except RecipeError as exc:raise core.BuildError(str(exc)) from exc
        kind=core.detect_project(root)
        package=recipe.package if recipe else core.source_package_hint(root,kind)
        if expected_package:
            core.validate_package_id(expected_package)
            if package and package.lower()!=expected_package.lower():
                raise core.BuildError('Selected package ID conflicts with the selected branch/recipe')
            package=expected_package
        expected=recipe.signer_sha256 if recipe else None
        profile=recipe.profile if recipe else None
    saved=False
    if package:
        if expected:
            saved=vault.load_for_certificate(package,expected) is not None
        else:
            saved=vault.load(package) is not None
    if saved:
        return MatchContext(repo,branch,package,expected,profile,True,(),(),False)
    if log:log('Searching local signing-key folders (certificate data only; no passwords)...')
    result=core.discover_signing_keys(folders)
    matched,unknown=match_candidates(result.candidates,expected)
    return MatchContext(repo,branch,package,expected,profile,False,matched,unknown,result.limited)
