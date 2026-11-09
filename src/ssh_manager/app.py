"""Command entry point for the native curses console."""
from __future__ import annotations
import argparse
import asyncio
import curses
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import sys
from . import __version__
from .controller import SSHManager
from .console import Console


def main():
    parser = argparse.ArgumentParser(description='Terminal SSH connection and key manager')
    parser.add_argument('--config',type=Path,help='SSH config path (default ~/.ssh/config)')
    parser.add_argument('--data-dir',type=Path,help='Separate inventory and encrypted vault location')
    parser.add_argument('--version',action='version',version='ssh-manager '+__version__)
    parser.add_argument('--migrate-vault',action='store_true',help='Migrate an older vault to OS-protected encryption, then exit')
    parser.add_argument('--legacy-key-file',type=Path,help='Previous version’s vault_key.py (migration only)')
    args = parser.parse_args()
    if args.legacy_key_file and not args.migrate_vault:parser.error('--legacy-key-file requires --migrate-vault')
    if args.migrate_vault:
        from .store import Vault
        from .paths import data_path
        import ast,getpass,json
        vault=Vault(args.data_dir or data_path())
        try:
            if not vault.path.exists():parser.error('No vault exists in this data directory.')
            if json.loads(vault.path.read_text()).get('protection')=='keyring':
                vault.open_automatic();print('Vault already uses OS-protected encryption.');return
            if args.legacy_key_file:
                source=args.legacy_key_file.read_text()
                if len(source)>65536:raise ValueError('Invalid legacy key file.')
                password=None
                for node in ast.parse(source).body:
                    if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='INTERNAL_VAULT_PASSWORD' for target in node.targets):
                        password=ast.literal_eval(node.value)
                if not isinstance(password,str):raise ValueError('No legacy vault password found in the supplied file.')
            else:password=getpass.getpass('Old vault password (one-time migration): ')
            backup=vault.migrate_to_automatic(password)
            print(f'Migrated and verified {len(vault.records)} saved passwords. Verified encrypted recovery copy: {backup}')
        except Exception as error:parser.exit(1,str(error)+'\n')
        finally:vault.lock()
        return
    if not shutil.which('ssh') or not shutil.which('ssh-keygen'):
        parser.error('OpenSSH (ssh and ssh-keygen) must be installed and on PATH.')
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run ssh-manager in an interactive terminal.')
    manager = SSHManager(args.config,args.data_dir)
    async def run(win):
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=8,thread_name_prefix='ssh-manager'))
        await Console(manager).run(win)
    try:
        curses.wrapper(lambda win: asyncio.run(run(win)))
    except KeyboardInterrupt:
        pass
    finally:
        manager.vault.lock()
        manager.store.db.close()


if __name__ == '__main__':
    main()
