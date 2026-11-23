"""PMS APK Builder GUI and CLI, packaged as a single-file Windows EXE."""
from __future__ import annotations

import argparse
import getpass
import os
import json
from pathlib import Path
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from pms_core import (
    VERSION, BuildError, SigningVault, create_release, detect_project,
    remote_branches, sdk_build_tools, tool, validate_repo, validate_branch, parse_repo_selection,
    publish_github_secrets, publish_project_github_secrets, SecretVault, vault_root,
    discover_signing_keys
)


def default_output() -> str:
    return str(Path.home()/'Downloads'/'PMS-Verified-APKs')


def sdk_preference_file() -> Path:
    return vault_root()/'settings.json'


def load_sdk_preference() -> str:
    try:
        cfg=json.loads(sdk_preference_file().read_text('utf8'))
        return str(cfg.get('sdkRoot','')) if cfg.get('format')==1 else ''
    except (OSError,ValueError,TypeError):
        return ''


def save_sdk_preference(directory: str) -> None:
    # Only a non-secret directory selection is persisted; signing secrets
    # and project build secrets stay in their separate encrypted vaults.
    filename=sdk_preference_file()
    filename.parent.mkdir(parents=True,exist_ok=True)
    temporary=filename.with_suffix('.tmp')
    temporary.write_text(json.dumps({'format':1,'sdkRoot':directory}),encoding='utf8')
    temporary.replace(filename)


def command_line() -> int:
    parser=argparse.ArgumentParser(description='PMS APK Builder — Android project build/sign/reuse keys')
    sub=parser.add_subparsers(dest='action',required=True)
    a=sub.add_parser('audit',help='check build tools, no modifications')
    a.add_argument('--sdk',help='optional Android SDK root directory')
    a=sub.add_parser('branches',help='list available GitHub branches')
    a.add_argument('--repo',required=True)
    a=sub.add_parser('build',help='isolated build and verify a signed APK')
    a.add_argument('--repo',required=True);a.add_argument('--branch',required=True)
    a.add_argument('--output',default=default_output());a.add_argument('--sdk',help='Android SDK root directory');a.add_argument('--type',default='auto',
        choices=('auto','flutter','capacitor','gradle','gradle-android'))
    a.add_argument('--authorize-new-signing-key',action='store_true',
       help='first-time signer ONLY; do not use for an already released app')
    a=sub.add_parser('find-keys',help='read-only search for existing signing keystores')
    a.add_argument('--folder',help='optional custom folder or drive to scan')
    a=sub.add_parser('keys',help='show package names with existing saved identities')
    a=sub.add_parser('secrets',help='list stored project environment-secret NAMES (never values)')
    a.add_argument('--repo',required=True)
    a=sub.add_parser('set-secret',help='save one encrypted build environment variable')
    a.add_argument('--repo',required=True);a.add_argument('--name',required=True)
    a=sub.add_parser('backup-secrets',help='export encrypted repository build-secrets backup')
    a.add_argument('--repo',required=True);a.add_argument('--output',required=True)
    a=sub.add_parser('restore-secrets',help='restore build secrets into an empty local repo vault')
    a.add_argument('--repo',required=True);a.add_argument('--file',required=True)
    a=sub.add_parser('backup',help='make an encrypted signing-key transfer backup')
    a.add_argument('--package',required=True);a.add_argument('--output',required=True)
    a=sub.add_parser('restore',help='restore a backed-up signing identity on another PC')
    a.add_argument('--file',required=True)
    a=sub.add_parser('import-key',help='import ORIGINAL existing PKCS12 signer for updates')
    a.add_argument('--package',required=True);a.add_argument('--keystore',required=True)
    a.add_argument('--alias',required=True)
    a=sub.add_parser('github-secrets',help='opt-in write-only GitHub Actions secrets upload')
    a.add_argument('--repo',required=True);a.add_argument('--package',required=True)
    a.add_argument('--confirm-upload',action='store_true')
    a.add_argument('--include-build-secrets',action='store_true')
    args=parser.parse_args()
    vault=SigningVault()
    try:
        if args.action=='audit':
            for name in ('git','java','keytool'):
                try: print(f'{name}: {tool(name)}')
                except BuildError as e:print(e)
            try:print('Android SDK build-tools:',sdk_build_tools(args.sdk or load_sdk_preference()))
            except BuildError as e:print(e)
            print('Signing vault:',vault.root)
            print('Stored signing identities:',', '.join(vault.list_packages()) or '(none)')
        elif args.action=='branches':
            validate_repo(args.repo)
            for item in remote_branches(args.repo):print(item)
        elif args.action=='keys':
            for item in vault.list_packages():print(item)
        elif args.action=='secrets':
            for item in SecretVault().names(args.repo):print(item)
        elif args.action=='set-secret':
            v=getpass.getpass('Enter secret value (hidden): ')
            if input('Type STORE to encrypt this value for the selected repository: ')!='STORE':
                raise BuildError('Build secret not stored')
            SecretVault().set(args.repo,args.name,v,confirm=True)
            print('Build secret saved securely:',args.name)
        elif args.action=='backup-secrets':
            v=getpass.getpass('Backup passphrase (12+ characters): ')
            v2=getpass.getpass('Repeat passphrase: ')
            if v!=v2:raise BuildError('Backup passphrases did not match')
            SecretVault().backup(args.repo,Path(args.output),v)
            print('Encrypted project build secrets backup saved')
        elif args.action=='restore-secrets':
            v=getpass.getpass('Backup passphrase: ')
            SecretVault().restore(Path(args.file),args.repo,v)
            print('Project build secrets restored')
        elif args.action=='build':
            validate_branch(args.branch)
            if args.authorize_new_signing_key:
                print('WARNING: A NEW signing key cannot update APKs previously signed by another key.')
                if input('Confirm NEW package/signer for first-time installation? Type CREATE: ')!='CREATE':
                    raise BuildError('Signing creation not authorized')
            info=create_release(args.repo,args.branch,Path(args.output),vault,
                 project_type=args.type,allow_new_key=args.authorize_new_signing_key,log=print,
                 sdk_root=args.sdk or load_sdk_preference())
            print('Build success:',info['apk'])
        elif args.action=='find-keys':
            scan=discover_signing_keys([Path(args.folder)] if args.folder else None)
            print(f'Found {len(scan.candidates)} candidate signing key files '
                  f'({scan.visited_entries} entries inspected).')
            for item in scan.candidates:
                print(str(item.path),f'({item.size_bytes} bytes)')
            if scan.limited:print('Search limit reached; choose a smaller --folder to continue.')
            print('Nothing was read, imported, signed or uploaded. Confirm alias and password before importing.')
        elif args.action=='backup':
            p1=getpass.getpass('Backup passphrase (12+ characters): ')
            p2=getpass.getpass('Repeat passphrase: ')
            if p1!=p2:raise BuildError('Passphrases did not match')
            vault.backup(args.package,Path(args.output),p1)
            print('Encrypted backup created; store it safely away from this PC.')
        elif args.action=='restore':
            key=getpass.getpass('Backup passphrase: ')
            restored=vault.restore(Path(args.file),key)
            print('Restored signer for',restored.package,'fingerprint',restored.fingerprint)
        elif args.action=='import-key':
            pw=getpass.getpass('Original signing keystore password: ')
            is_jks=Path(args.keystore).is_file() and Path(args.keystore).open('rb').read(4)==b'\xfe\xed\xfe\xed'
            kp=getpass.getpass('JKS private-key password (Enter = same as store): ') if is_jks else None
            loaded=vault.import_existing(args.package,Path(args.keystore),args.alias,pw,key_password=kp)
            print('Imported signing key for',loaded.package,'fingerprint',loaded.fingerprint)
        elif args.action=='github-secrets':
            if not args.confirm_upload:raise BuildError('Use --confirm-upload for explicit GitHub Actions secrets upload')
            print('WARNING: GitHub repo workflows with access to these Actions secrets can use your signing key.')
            print('GitHub secrets cannot be read back or used to restore signing keys.')
            if input('Type UPLOAD to set Actions secrets for this repository: ')!='UPLOAD':
                raise BuildError('No secrets uploaded')
            publish_github_secrets(args.repo,args.package,vault,confirm=True,log=print)
            if args.include_build_secrets:
                publish_project_github_secrets(args.repo,SecretVault(),confirm=True,log=print)
        return 0
    except BuildError as e:
        print('SAFE STOP:',e,file=sys.stderr)
        return 1


class PMSApp:
    def __init__(self,root:tk.Tk):
        self.root=root
        root.title('PMS APK Builder — portable v'+VERSION)
        root.geometry('930x740')
        root.minsize(800,610)
        self.repo=tk.StringVar()
        self.branch=tk.StringVar(value='main')
        self.output=tk.StringVar(value=default_output())
        self.sdk_root=tk.StringVar(value=load_sdk_preference())
        self.project_type=tk.StringVar(value='auto')
        self.new_key=tk.BooleanVar(value=False)
        self.package=tk.StringVar()
        self.console=queue.Queue()
        self.busy=False
        self.make_ui()
        root.after(90,self.consume)

    def make_ui(self):
        pad={'padx':12,'pady':5}
        frame=ttk.Frame(self.root,padding=14)
        frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='PMS APK BUILDER',font=('Segoe UI',18,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Select any supported Android GitHub repository and branch. Build in an isolated checkout; reuse a verified signer.').pack(anchor='w',pady=(0,10))
        g=ttk.Frame(frame);g.pack(fill='x')
        ttk.Label(g,text='GitHub repo URL').grid(row=0,column=0,sticky='w',**pad)
        ttk.Entry(g,textvariable=self.repo).grid(row=0,column=1,sticky='ew',**pad)
        ttk.Button(g,text='Get branches',command=self.branches).grid(row=0,column=2,**pad)
        ttk.Label(g,text='Branch').grid(row=1,column=0,sticky='w',**pad)
        self.branches_cb=ttk.Combobox(g,textvariable=self.branch)
        self.branches_cb.grid(row=1,column=1,sticky='ew',**pad)
        ttk.Label(g,text='Project type').grid(row=2,column=0,sticky='w',**pad)
        ttk.Combobox(g,textvariable=self.project_type,state='readonly',values=[
            'auto','flutter','capacitor','gradle','gradle-android']).grid(row=2,column=1,sticky='ew',**pad)
        ttk.Label(g,text='APK output').grid(row=3,column=0,sticky='w',**pad)
        ttk.Entry(g,textvariable=self.output).grid(row=3,column=1,sticky='ew',**pad)
        ttk.Button(g,text='Browse',command=self.choose_output).grid(row=3,column=2,**pad)
        ttk.Label(g,text='Existing package ID / signer').grid(row=4,column=0,sticky='w',**pad)
        ttk.Entry(g,textvariable=self.package).grid(row=4,column=1,sticky='ew',**pad)
        ttk.Button(g,text='Saved keys',command=self.show_keys).grid(row=4,column=2,**pad)
        ttk.Label(g,text='Android SDK folder').grid(row=5,column=0,sticky='w',**pad)
        ttk.Entry(g,textvariable=self.sdk_root).grid(row=5,column=1,sticky='ew',**pad)
        ttk.Button(g,text='Find / Select SDK',command=self.choose_sdk).grid(row=5,column=2,**pad)
        g.columnconfigure(1,weight=1)
        ttk.Checkbutton(frame,text='Allow NEW signing key automatically if none exists (FIRST RELEASE ONLY)',
                        variable=self.new_key).pack(anchor='w',padx=12,pady=(8,8))
        ttk.Label(frame,text='Enter https://github.com/owner/repository; choose any branch. SDK folder is auto-detected unless set.',
                  foreground='#46556a').pack(anchor='w',padx=12)
        ttk.Label(frame,text='Existing published app? Import its ORIGINAL signing key first. Never replace a lost signer.',
                  foreground='#a14b16').pack(anchor='w',padx=12)
        buttons=ttk.Frame(frame);buttons.pack(fill='x',pady=12)
        self.buildbutton=ttk.Button(buttons,text='BUILD AND VERIFY APK',command=self.build)
        self.buildbutton.pack(side='left',padx=(0,10))
        for label,fn in [('Audit tools',self.audit),('Find signing keys',self.find_signing_keys),
                         ('Import key',self.import_key),('Backup key',self.backup),
                         ('Restore key',self.restore)]:
            ttk.Button(buttons,text=label,command=fn).pack(side='left',padx=3)
        secrets_buttons=ttk.Frame(frame);secrets_buttons.pack(fill='x',pady=(0,10))
        for label,fn in [('Save build secret',self.save_build_secret),
                         ('Backup build secrets',self.backup_build_secrets),
                         ('GitHub Actions secrets',self.github_secrets)]:
            ttk.Button(secrets_buttons,text=label,command=fn).pack(side='left',padx=3)
        ttk.Label(frame,text='Build log (no keys or passwords are displayed)').pack(anchor='w')
        self.log_widget=tk.Text(frame,height=16,state='disabled',wrap='word',font=('Consolas',10))
        self.log_widget.pack(fill='both',expand=True)
        ttk.Label(frame,text='Portable EXE needs Git/JDK/Android SDK and the framework toolchain. GitHub secrets are optional and write-only.').pack(anchor='w',pady=8)

    def log(self,txt):
        self.console.put(('log',str(txt)))

    def consume(self):
        try:
            while True:
                op,value=self.console.get_nowait()
                if op=='log':
                    self.log_widget.configure(state='normal')
                    self.log_widget.insert('end',value+'\n')
                    self.log_widget.see('end')
                    self.log_widget.configure(state='disabled')
                elif op=='done':
                    self.busy=False
                    self.buildbutton.configure(state='normal')
                    success,kind=value
                    if success and kind=='apk':
                        messagebox.showinfo('PMS APK Builder','Signed APK built and verified.')
        except queue.Empty:pass
        self.root.after(90,self.consume)

    def worker(self,task,*,completion='task'):
        if self.busy:
            messagebox.showwarning('Busy','A build or branch request is already running.');return
        self.busy=True
        self.buildbutton.configure(state='disabled')
        def job():
            ok=False
            try:task();ok=True
            except BuildError as e:self.log('SAFE STOP: '+str(e))
            except Exception as e:self.log('SAFE STOP: unexpected error ('+type(e).__name__+'). No APK declared verified.')
            finally:self.console.put(('done',(ok,completion)))
        threading.Thread(target=job,daemon=True).start()

    def choose_output(self):
        p=filedialog.askdirectory(initialdir=self.output.get() if Path(self.output.get()).exists() else str(Path.home()))
        if p:self.output.set(p)

    def choose_sdk(self):
        selection=filedialog.askdirectory(title='Select Android SDK root (contains build-tools)',
             initialdir=self.sdk_root.get() if self.sdk_root.get() and Path(self.sdk_root.get()).is_dir() else str(Path.home()))
        if not selection:return
        try:
            found=sdk_build_tools(selection)
        except BuildError as err:
            messagebox.showwarning('Android SDK folder',str(err));return
        self.sdk_root.set(selection)
        save_sdk_preference(selection)
        self.log('SDK selected: '+str(found['aapt'].parent))

    def branches(self):
        repo=self.repo.get().strip()
        try:_,_,branch_hint=parse_repo_selection(repo)
        except BuildError as err:
            messagebox.showwarning('GitHub repository',str(err));return

        def task():
            names=remote_branches(repo)
            self.log(f'Found {len(names)} branches')
            def set_branches():
                self.branches_cb.configure(values=names)
                if branch_hint and branch_hint in names:
                    self.branch.set(branch_hint)
                elif names and self.branch.get() not in names:
                    self.branch.set('main' if 'main' in names else names[0])
            self.root.after(0,set_branches)
        self.worker(task)

    def audit(self):
        for name in ('git','java','keytool','flutter','npm','gh'):
            try:self.log(name+': '+tool(name))
            except BuildError:self.log(name+': not installed (may be optional)')
        try:self.log('Android SDK build-tools: '+str(sdk_build_tools(self.sdk_root.get())))
        except BuildError as e:self.log('SDK: '+str(e))
        self.show_keys()

    def show_keys(self):
        keys=SigningVault().list_packages()
        self.log('Saved signer packages: '+(', '.join(keys) if keys else '(none)'))

    def require_package(self):
        package=self.package.get().strip()
        if not package:
            messagebox.showwarning('Package ID','Enter your Android application package ID.');return None
        return package

    def build(self):
        repo=self.repo.get().strip();branch=self.branch.get().strip();output=self.output.get();kind=self.project_type.get()
        try:
            _,_,branch_hint=parse_repo_selection(repo)
            if branch_hint and (not branch or branch=='main'):
                branch=branch_hint
                self.branch.set(branch_hint)
            validate_branch(branch)
        except BuildError as err:
            messagebox.showwarning('Select a GitHub repository and branch',str(err));return
        authorize=self.new_key.get()
        if authorize and not messagebox.askyesno('First-release signing ONLY',
            'A NEW signer cannot update any existing installed app signed by another key.\n\n'
            'Create a new signer only when this app has never been published or installed with another signer. Continue?'):
            return
        def task():
            r=create_release(repo,branch,Path(output),SigningVault(),project_type=kind,
                             allow_new_key=authorize,log=self.log,sdk_root=self.sdk_root.get())
            self.log('SUCCESS: '+r['apk'])
        self.worker(task,completion='apk')

    def find_signing_keys(self):
        # Default: common current-user folders; custom folder scan is optional.
        # Do not open key bytes, try passwords or send filenames anywhere.
        options=messagebox.askyesnocancel('Find original signing keys',
            'Search common folders in this Windows account for .jks, .keystore, .p12, .pfx and .pkcs12 files?\n\n'
            'YES: Standard user folders.\nNO: Choose a different folder or drive.\nCANCEL: Stop.\n\n'
            'This searches filenames locally; it does NOT import or upload any keys.')
        if options is None:return
        if options:folders=None
        else:
            folder=filedialog.askdirectory(title='Select a folder or drive to search for signing keys',
                                            initialdir=str(Path.home()))
            if not folder:return
            folders=[Path(folder)]
        def task():
            result=discover_signing_keys(folders)
            self.log(f'Signing key search: {len(result.candidates)} candidate files found (local only).')
            if result.limited:self.log('Search limit reached; choose a smaller folder to continue.')
            self.root.after(0,lambda:self.show_found_signing_keys(result))
        self.worker(task)

    def show_found_signing_keys(self, result):
        dialog=tk.Toplevel(self.root)
        dialog.title('Existing signing key candidates — read only')
        dialog.geometry('940x440')
        dialog.transient(self.root)
        heading='Select the ORIGINAL key for your Android package. No key is imported until you approve it.'
        ttk.Label(dialog,text=heading).pack(anchor='w',padx=12,pady=10)
        area=ttk.Frame(dialog);area.pack(fill='both',expand=True,padx=12,pady=6)
        keys=ttk.Treeview(area,columns=('file','folder','size'),show='headings',selectmode='browse')
        for name,title,width in [('file','Key file',200),('folder','Local folder',570),('size','Bytes',90)]:
            keys.heading(name,text=title);keys.column(name,width=width,stretch=name=='folder')
        bar=ttk.Scrollbar(area,orient='vertical',command=keys.yview)
        keys.configure(yscrollcommand=bar.set)
        keys.pack(side='left',fill='both',expand=True);bar.pack(side='right',fill='y')
        found={}
        for n,candidate in enumerate(result.candidates):
            ident=f'key{n}'
            found[ident]=candidate.path
            keys.insert('', 'end',iid=ident,values=(candidate.path.name,str(candidate.path.parent),str(candidate.size_bytes)))
        label='Found '+str(len(found))+' candidate files. Only checked locations were searched.'
        if result.limited:label+=' Search limit reached; choose a narrower folder.'
        ttk.Label(dialog,text=label).pack(anchor='w',padx=12,pady=4)
        controls=ttk.Frame(dialog);controls.pack(fill='x',padx=12,pady=(4,12))
        def use_selected():
            selected=keys.selection()
            if not selected:
                messagebox.showwarning('Select a key','Choose a keystore file first.',parent=dialog);return
            candidate=found[selected[0]]
            if not messagebox.askyesno('Confirm ORIGINAL key',
                'Import this key for the package ID you entered?\n\n'
                'Do not replace a released application signer. The certificate will be verified after import.',parent=dialog):return
            dialog.destroy()
            self.import_key(candidate)
        ttk.Button(controls,text='Use selected signing key',command=use_selected).pack(side='left')
        ttk.Button(controls,text='Close',command=dialog.destroy).pack(side='right')

    def import_key(self, selected_path=None):
        package=self.require_package()
        if not package:return
        file=str(selected_path) if selected_path is not None else filedialog.askopenfilename(
            title='Select ORIGINAL Android signing keystore',
            filetypes=[('Android signing keys','*.jks *.keystore *.p12 *.pfx *.pkcs12'),('All files','*.*')])
        if not file:return
        alias=tk.simpledialog.askstring('Alias','Original signing-key alias:',parent=self.root)
        if not alias:return
        password=tk.simpledialog.askstring('Key password','Original keystore password:',show='*',parent=self.root)
        if password is None:return
        try:
            with Path(file).open('rb') as fp:is_jks=fp.read(4)==b'\xfe\xed\xfe\xed'
        except OSError:
            messagebox.showwarning('Signing key','Cannot read selected keystore file.');return
        key_password=None
        if is_jks:
            key_password=tk.simpledialog.askstring('JKS key password',
                'Private-key password (leave blank if the SAME as keystore password):',
                show='*',parent=self.root)
            if key_password is None:return
        self.worker(lambda:self.log('Imported original signer: '+SigningVault().import_existing(
            package,Path(file),alias,password,key_password=key_password).fingerprint))

    def backup(self):
        package=self.require_package()
        if not package:return
        file=filedialog.asksaveasfilename(defaultextension='.pmskey',filetypes=[('PMS encrypted key backup','*.pmskey')])
        if not file:return
        pw=tk.simpledialog.askstring('Encrypt backup','Set a strong 12+ character backup passphrase:',show='*',parent=self.root)
        if not pw:return
        if not messagebox.askyesno('Confirm backup','Save encrypted signer backup to the selected folder? Store the passphrase separately.'):
            return
        self.worker(lambda:(SigningVault().backup(package,Path(file),pw),self.log('Encrypted backup created: '+file)))

    def restore(self):
        file=filedialog.askopenfilename(filetypes=[('PMS encrypted key backup','*.pmskey')])
        if not file:return
        pw=tk.simpledialog.askstring('Decrypt backup','Backup passphrase:',show='*',parent=self.root)
        if not pw:return
        self.worker(lambda:self.log('Restored original signer: '+SigningVault().restore(Path(file),pw).package))

    def save_build_secret(self):
        repo=self.repo.get()
        try:validate_repo(repo)
        except BuildError as e:
            messagebox.showwarning('GitHub repository',str(e));return
        name=tk.simpledialog.askstring('Build environment secret','Environment variable NAME (UPPERCASE):',parent=self.root)
        if not name:return
        value=tk.simpledialog.askstring('Build secret value','Value (hidden; will be supplied only to this repository build):',
                                       show='*',parent=self.root)
        if not value:return
        if not messagebox.askyesno('Save encrypted build secret',
            'Build scripts from this repository can read this secret. Only build repositories you trust.\n\nSave locally encrypted for future builds?'):
            return
        self.worker(lambda:(SecretVault().set(repo,name,value,confirm=True),self.log('Build secret saved: '+name)))

    def backup_build_secrets(self):
        repo=self.repo.get()
        try:validate_repo(repo)
        except BuildError as e:
            messagebox.showwarning('GitHub repository',str(e));return
        file=filedialog.asksaveasfilename(defaultextension='.pmsenv',filetypes=[('Encrypted project secrets','*.pmsenv')])
        if not file:return
        pw=tk.simpledialog.askstring('Encrypt build secrets','Backup passphrase (12+ characters):',
                                      show='*',parent=self.root)
        if not pw:return
        self.worker(lambda:(SecretVault().backup(repo,Path(file),pw),self.log('Encrypted project secrets backup created')))

    def github_secrets(self):
        package=self.require_package()
        if not package:return
        repo=self.repo.get()
        if not messagebox.askyesno('Explicit GitHub secret upload',
            'Upload this signer to GitHub Actions secrets of the selected repository?\n\n'
            'Repository maintainers and workflows with access to those secrets may sign APKs.\n'
            'GitHub Actions secrets are NOT a recoverable backup. Continue?'):
            return
        include=messagebox.askyesno('Optional build environment secrets',
          'Also upload all saved repository build environment secrets?\nOnly workflows for this repository should use these secrets.')
        def task():
            publish_github_secrets(repo,package,SigningVault(),confirm=True,log=self.log)
            if include and SecretVault().names(repo):
                publish_project_github_secrets(repo,SecretVault(),confirm=True,log=self.log)
        self.worker(task)


def main():
    if len(sys.argv)>1:return command_line()
    root=tk.Tk()
    # use an explicit import so tk.simpledialog works when bundled by PyInstaller.
    import tkinter.simpledialog
    root.withdraw()
    root.deiconify()
    PMSApp(root)
    root.mainloop()
    return 0


if __name__=='__main__':raise SystemExit(main())
