"""PMS APK Builder GUI and CLI, packaged as a single-file Windows EXE."""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from pms_core import (
    VERSION, BuildError, SigningVault, create_release, detect_project,
    remote_branches, sdk_build_tools, tool, validate_repo, validate_branch,
    publish_github_secrets, vault_root
)


def default_output() -> str:
    return str(Path.home()/'Downloads'/'PMS-Verified-APKs')


def command_line() -> int:
    parser=argparse.ArgumentParser(description='PMS APK Builder — Android project build/sign/reuse keys')
    sub=parser.add_subparsers(dest='action',required=True)
    a=sub.add_parser('audit',help='check build tools, no modifications')
    a=sub.add_parser('branches',help='list available GitHub branches')
    a.add_argument('--repo',required=True)
    a=sub.add_parser('build',help='isolated build and verify a signed APK')
    a.add_argument('--repo',required=True);a.add_argument('--branch',required=True)
    a.add_argument('--output',default=default_output());a.add_argument('--type',default='auto',
        choices=('auto','flutter','capacitor','gradle','gradle-android'))
    a.add_argument('--authorize-new-signing-key',action='store_true',
       help='first-time signer ONLY; do not use for an already released app')
    a=sub.add_parser('keys',help='show package names with existing saved identities')
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
    args=parser.parse_args()
    vault=SigningVault()
    try:
        if args.action=='audit':
            for name in ('git','java','keytool'):
                try: print(f'{name}: {tool(name)}')
                except BuildError as e:print(e)
            try:print('Android SDK build-tools:',sdk_build_tools())
            except BuildError as e:print(e)
            print('Signing vault:',vault.root)
            print('Stored signing identities:',', '.join(vault.list_packages()) or '(none)')
        elif args.action=='branches':
            validate_repo(args.repo)
            for item in remote_branches(args.repo):print(item)
        elif args.action=='keys':
            for item in vault.list_packages():print(item)
        elif args.action=='build':
            validate_branch(args.branch)
            if args.authorize_new_signing_key:
                print('WARNING: A NEW signing key cannot update APKs previously signed by another key.')
                if input('Confirm NEW package/signer for first-time installation? Type CREATE: ')!='CREATE':
                    raise BuildError('Signing creation not authorized')
            info=create_release(args.repo,args.branch,Path(args.output),vault,
                 project_type=args.type,allow_new_key=args.authorize_new_signing_key,log=print)
            print('Build success:',info['apk'])
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
            pw=getpass.getpass('Original PKCS12 signing password: ')
            loaded=vault.import_existing(args.package,Path(args.keystore),args.alias,pw)
            print('Imported signing key for',loaded.package,'fingerprint',loaded.fingerprint)
        elif args.action=='github-secrets':
            if not args.confirm_upload:raise BuildError('Use --confirm-upload for explicit GitHub Actions secrets upload')
            print('WARNING: GitHub repo workflows with access to these Actions secrets can use your signing key.')
            print('GitHub secrets cannot be read back or used to restore signing keys.')
            if input('Type UPLOAD to set Actions secrets for this repository: ')!='UPLOAD':
                raise BuildError('No secrets uploaded')
            publish_github_secrets(args.repo,args.package,vault,confirm=True,log=print)
        return 0
    except BuildError as e:
        print('SAFE STOP:',e,file=sys.stderr)
        return 1


class PMSApp:
    def __init__(self,root:tk.Tk):
        self.root=root
        root.title('PMS APK Builder — portable v'+VERSION)
        root.geometry('790x680')
        root.minsize(650,580)
        self.repo=tk.StringVar()
        self.branch=tk.StringVar(value='main')
        self.output=tk.StringVar(value=default_output())
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
        g.columnconfigure(1,weight=1)
        ttk.Checkbutton(frame,text='Allow NEW signing key automatically if none exists (FIRST RELEASE ONLY)',
                        variable=self.new_key).pack(anchor='w',padx=12,pady=(8,8))
        ttk.Label(frame,text='Existing published app? Import its ORIGINAL signing key first. Never replace a lost signer.',
                  foreground='#a14b16').pack(anchor='w',padx=12)
        buttons=ttk.Frame(frame);buttons.pack(fill='x',pady=12)
        self.buildbutton=ttk.Button(buttons,text='BUILD AND VERIFY APK',command=self.build)
        self.buildbutton.pack(side='left',padx=(0,10))
        for label,fn in [('Audit tools',self.audit),('Import key',self.import_key),
                         ('Backup key',self.backup),('Restore key',self.restore),
                         ('GitHub secrets',self.github_secrets)]:
            ttk.Button(buttons,text=label,command=fn).pack(side='left',padx=3)
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
                    if value:messagebox.showinfo('PMS APK Builder','Verified APK completed.')
        except queue.Empty:pass
        self.root.after(90,self.consume)

    def worker(self,task):
        if self.busy:
            messagebox.showwarning('Busy','A build or branch request is already running.');return
        self.busy=True
        self.buildbutton.configure(state='disabled')
        def job():
            ok=False
            try:task();ok=True
            except BuildError as e:self.log('SAFE STOP: '+str(e))
            except Exception as e:self.log('SAFE STOP: unexpected error ('+type(e).__name__+'). No APK declared verified.')
            finally:self.console.put(('done',ok))
        threading.Thread(target=job,daemon=True).start()

    def choose_output(self):
        p=filedialog.askdirectory(initialdir=self.output.get() if Path(self.output.get()).exists() else str(Path.home()))
        if p:self.output.set(p)

    def branches(self):
        repo=self.repo.get()
        def task():
            names=remote_branches(repo)
            self.log(f'Found {len(names)} branches')
            self.root.after(0,lambda:self.branches_cb.configure(values=names))
        self.worker(task)

    def audit(self):
        for name in ('git','java','keytool','flutter','npm','gh'):
            try:self.log(name+': '+tool(name))
            except BuildError:self.log(name+': not installed (may be optional)')
        try:self.log('Android SDK build-tools: '+str(sdk_build_tools()))
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
        repo=self.repo.get();branch=self.branch.get();output=self.output.get();kind=self.project_type.get()
        authorize=self.new_key.get()
        if authorize and not messagebox.askyesno('First-release signing ONLY',
            'A NEW signer cannot update any existing installed app signed by another key.\n\n'
            'Create a new signer only when this app has never been published or installed with another signer. Continue?'):
            return
        def task():
            r=create_release(repo,branch,Path(output),SigningVault(),project_type=kind,
                             allow_new_key=authorize,log=self.log)
            self.log('SUCCESS: '+r['apk'])
        self.worker(task)

    def import_key(self):
        package=self.require_package()
        if not package:return
        file=filedialog.askopenfilename(title='Select ORIGINAL PKCS12 release key',filetypes=[('PKCS12','*.p12 *.pfx'),('All files','*.*')])
        if not file:return
        alias=tk.simpledialog.askstring('Alias','Original keystore alias:',parent=self.root)
        if not alias:return
        password=tk.simpledialog.askstring('Key password','Original signing key password:',show='*',parent=self.root)
        if password is None:return
        self.worker(lambda:self.log('Imported signer: '+SigningVault().import_existing(package,Path(file),alias,password).fingerprint))

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

    def github_secrets(self):
        package=self.require_package()
        if not package:return
        repo=self.repo.get()
        if not messagebox.askyesno('Explicit GitHub secret upload',
            'Upload this signer to GitHub Actions secrets of the selected repository?\n\n'
            'Repository maintainers and workflows with access to those secrets may sign APKs.\n'
            'GitHub Actions secrets are NOT a recoverable backup. Continue?'):
            return
        self.worker(lambda:publish_github_secrets(repo,package,SigningVault(),confirm=True,log=self.log))


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
