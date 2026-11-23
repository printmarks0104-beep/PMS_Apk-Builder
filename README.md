# PMS APK Builder

**Portable Android APK builder for supported GitHub repositories.** It contains no project keys, private content, payment overrides, hard-coded repository, or approved branch list. You select the repository and branch at run time. All builds take place in a temporary isolated checkout and the GitHub source remains untouched.

## Get the portable Windows EXE

Open [Actions → Build portable Windows EXE](https://github.com/printmarks0104-beep/PMS_Apk-Builder/actions/workflows/portable-exe.yml), run the workflow or choose the most recent successful run, then download `PMS-Apk-Builder-Windows-Portable`. Extract it and open **`PMS-Apk-Builder.exe`**. **No Python installation is needed** on the destination PC. The EXE does not write to Program Files or require an installer.

**External toolchains are still required**: Git, JDK with `keytool`, Android SDK build-tools (`aapt`, `zipalign`, `apksigner`), and one framework toolchain (Flutter, Node/npm with Capacitor, or the repository's Gradle wrapper). Those tools are not bundled inside the portable EXE. Flutter/Capacitor/Gradle projects can require additional Android SDK platform/build packages, licenses or local Java configuration. A standalone EXE cannot make an unsupported repository into an Android app.

## What it supports

| Source repository | Build route | Requirements |
|---|---|---|
| Flutter app with `pubspec.yaml`, `android/` | `flutter pub get`, `flutter build apk --release` | Flutter SDK, JDK, Android SDK |
| Capacitor app with lockfile/config | `npm ci`, `npm run build`, `npx --no-install cap sync android`, Gradle | Node/npm, Capacitor project dependencies, Android SDK/JDK |
| Gradle Android application | repository `gradlew[.bat] assembleRelease` | JDK, Android SDK |

The builder signs the **final APK** using the same saved PKCS12 identity for that Android application ID. It checks zip alignment, Android package ID, signer certificate SHA-256, apksigner verification and final file SHA-256, then saves a provenance JSON manifest. It refuses to guess when a project builds multiple APKs or variants. Version codes/names, SDK compatibility, flavor, permissions and release behavior are controlled by the selected repository; adjust and test them there. An APK build does **not** imply the application works on a device.

## Signing keys: important

- On an application's **first ever release only**, choose `Allow NEW signing key` and explicitly approve the warning. This generates an RSA-3072 PKCS12 signing identity with `keytool`. It is stored under `%LOCALAPPDATA%\PMS-Apk-Builder\signing\<application-id>\`.
- For **existing published apps**, turn OFF new-key creation and import the **original PKCS12 key** and alias first. A new signing identity **cannot update an already-installed app signed with a different key**. JKS users should convert their existing keystore to PKCS12 with keytool and preserve the original keystore/certificate.
- The keystore password is randomly generated and encrypted using **Windows DPAPI** for the current Windows user. No plaintext key/password is stored in GitHub, this EXE folder, source checkout, or build logs.
- For another PC, use `Backup key` with a strong passphrase and store the `.pmskey` file **offline** in a secure backup location. It encrypts both the key and password using AES-256-GCM and scrypt. Use `Restore key` on the new PC. **Store the passphrase separately**; there is no recovery if both passphrase and key are lost.
- The vault intentionally refuses to overwrite any existing identity. One package ID maps to one pinned certificate. An app may use different certificates for independent release variants only if they have separate package IDs.
- GitHub **Actions Secrets** are an **optional, explicit opt-in** convenience for CI, not recoverable storage. They can be used by repository workflows and admins with sufficient access can change those workflows. They are *not* a safe replacement for your offline encrypted backup. Never commit private keys in a GitHub folder or file, **even if the repo is private**.

## Reusable build environment secrets

Use **Save build secret** to store a build-only environment variable (for example `API_PUBLIC_TOKEN`) for the selected GitHub repository. It is encrypted locally with Windows DPAPI, supplied only to that repository's build subprocesses and not committed into source. Only enter secrets for repositories **you trust**, because npm/Gradle/Flutter scripts can read and potentially exfiltrate environment variables. Console output attempts to redact exact secret values; no logger can guarantee detection of deliberately transformed/exfiltrated secrets.

Use **Backup build secrets** to create a separately encrypted `.pmsenv` file for transfer. The repository name and passphrase are required to restore it using `restore-secrets`; restores never replace existing saved secrets. GitHub Actions upload is a separate explicit opt-in for a selected repository, and GitHub secrets cannot be downloaded back. Never publish these files or commit them to Git.

## User workflow

1. Launch `PMS-Apk-Builder.exe`. Select your `https://github.com/owner/repo`, then **Get branches**, and choose a branch.
2. Use **Audit tools** to see missing dependencies. Set output folder and leave project type as **auto** unless needed.
3. If updating an existing app, **Import key** first; otherwise authorize automatic creation for a truly new app.
4. **BUILD AND VERIFY APK**. An APK is declared successful only if build, signing, certificate and package validation all pass.
5. Immediately export an **encrypted signing backup**, store it off-PC, and confirm you can restore it on a separate test PC before publishing your app.

Nothing is uploaded to GitHub by a local build. The repository can be public or private, provided your Windows Git authentication permits clone. **Do not build untrusted repositories**: Gradle, npm and Flutter build scripts execute third-party code on your PC.

## Optional GitHub Actions Secrets

The **GitHub secrets** button or `github-secrets` CLI action requires an explicit warning confirmation. It uses an authenticated `gh` CLI and uploads through STDIN, never command-line arguments. It writes `PMS_SIGNING_P12_BASE64`, `PMS_SIGNING_PASSWORD`, `PMS_SIGNING_ALIAS`, `PMS_SIGNING_PACKAGE`, and `PMS_SIGNING_CERT_SHA256` to the **selected application repository's Actions secrets**, not PMS APK Builder itself. Only configure this in a repository whose maintainers/workflows you trust. Avoid exposing Actions secrets to forked pull requests or untrusted build scripts. GitHub won't reveal the secret values back to you. With explicit approval it can also upload the encrypted local project environment-secret values as GitHub Actions secrets. This tool does not automatically add a signing workflow to the application repo.

## CLI / local development

```powershell
python -m pip install -r requirements.txt
python pms_builder.py                         # GUI
python pms_builder.py audit
python pms_builder.py branches --repo https://github.com/owner/project
python pms_builder.py build --repo https://github.com/owner/project --branch feature/my-branch --output C:\\APK-output
python pms_builder.py keys
python pms_builder.py secrets --repo https://github.com/owner/project
python pms_builder.py set-secret --repo https://github.com/owner/project --name API_PUBLIC_TOKEN
python pms_builder.py backup-secrets --repo https://github.com/owner/project --output C:\Backups\project.pmsenv
python pms_builder.py restore-secrets --repo https://github.com/owner/project --file C:\Backups\project.pmsenv
python pms_builder.py backup --package com.example.app --output C:\\Backups\\app.pmskey
python pms_builder.py restore --file C:\\Backups\\app.pmskey
python pms_builder.py import-key --package com.example.app --keystore C:\\secure\\original.p12 --alias release
python pms_builder.py github-secrets --repo https://github.com/owner/project --package com.example.app --confirm-upload --include-build-secrets
python -m unittest discover -s tests -v
```

To build the EXE locally (on Windows): `python -m pip install -r requirements-build.txt` then `pyinstaller --noconfirm --clean --onefile --windowed --name PMS-Apk-Builder --hidden-import tkinter.simpledialog pms_builder.py`. GitHub Actions packages the same files as a portable ZIP automatically.

## Limits and safety

- Only **Windows 10/11** for the EXE's local signing vault (Windows DPAPI). The source can run tests on Linux, but local signing storage requires Windows.
- **GitHub HTTPS URLs** only for project selection; any GitHub branch is supported if it contains a recognized Android app. No hard-coded brand or branch exceptions. The selected repo must permit authorized access.
- Toolchains must be installed; this release does not auto-download SDK binaries, Java, Flutter, or Node, or request elevation.
- App-specific build profiles/variants, multi-module selection, Google Play App Signing upload-key rules, managed signing, multiple APK splits and AAB releases require explicit per-project support and are **not** silently bypassed.
- This project does not move application private assets or secrets from the uploaded legacy builder into the new repository. Do not put passwords, songbook keys, or API tokens in app source or this repository.
- Always test installed APKs on an actual Android device, and verify the target app’s licensing, premium flags and payments independently; this tool does not grant or bypass entitlements.
