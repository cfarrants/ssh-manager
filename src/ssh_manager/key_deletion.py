"""Remove a local key pair, retaining a protected recovery copy."""
from pathlib import Path
import shutil
import uuid
from .remote import local_keys


def remove_key_files(public_path, fingerprint, directory):
    public=Path(public_path).expanduser()
    private=public.with_suffix('')
    current=local_keys(public.parent,[str(public)])
    if not any(k['path']==str(public) and k['fingerprint']==fingerprint for k in current):
        raise ValueError('The key changed or disappeared. Refresh the key list before deleting.')
    recovery=Path(directory)/'deleted-keys'/uuid.uuid4().hex
    recovery.mkdir(parents=True,mode=0o700)
    recovery.parent.chmod(0o700)
    moved=[]
    try:
        for path in (private,public):
            if not path.exists() and not path.is_symlink():continue
            target=recovery/path.name
            shutil.move(str(path),str(target))
            moved.append((path,target))
            if not target.is_symlink():target.chmod(0o600)
    except Exception:
        for path,target in reversed(moved):
            if not path.exists() and not path.is_symlink():shutil.move(str(target),str(path))
        raise
    return recovery
