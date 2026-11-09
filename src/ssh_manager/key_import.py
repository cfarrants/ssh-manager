"""Validate and copy SSH keys without overwriting existing files."""
import os
from pathlib import Path
import subprocess
import tempfile


def import_key(source, directory, filename, passphrase=''):
    source=Path(source).expanduser()
    filename=filename.strip()
    if not filename or filename in ('.','..') or Path(filename).name!=filename or '/' in filename or '\\' in filename:
        raise ValueError('Enter a filename without folders.')
    if any(c in passphrase for c in '\r\n\x00'):
        raise ValueError('Passphrase must be a single line.')
    if not source.is_file() or source.stat().st_size>1024*1024:
        raise ValueError('Select a readable SSH key file smaller than 1 MB.')
    content=source.read_bytes()
    private=b'PRIVATE KEY-----' in content[:100]
    if not private:
        raise ValueError('Select an SSH private key, not a public key or other file.')
    filename=filename.removesuffix('.pub')
    if not filename:
        raise ValueError('Enter a filename.')
    target=Path(directory)/filename
    public_target=target.with_name(target.name+'.pub')
    if os.path.lexists(target) or os.path.lexists(public_target):
        raise ValueError('This key filename already exists. Choose another name; nothing was overwritten.')
    if private:
        # Browser downloads may be world-readable. Validate a protected temporary
        # copy rather than weakening OpenSSH checks or changing the original file.
        with tempfile.TemporaryDirectory(prefix='sm-key-import-') as temporary:
            protected=Path(temporary)/'private-key'
            fd=os.open(protected,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write(content)
            result=subprocess.run(['ssh-keygen','-y','-f',str(protected)],input=passphrase+'\n',text=True,capture_output=True,start_new_session=os.name!='nt',timeout=20)
        if result.returncode:
            raise ValueError('Cannot open this private key. Check its format and passphrase.')
        public=result.stdout.strip()
        companion=source.with_name(source.name+'.pub')
        if companion.is_file():
            if companion.stat().st_size>1024*1024:
                raise ValueError('The matching public key file is too large.')
            supplied=companion.read_text().strip()
            if len(supplied.splitlines())!=1 or supplied.split()[:2]!=public.split()[:2]:
                raise ValueError('The matching .pub file does not belong to this private key.')
            public=supplied
    if len(public.splitlines())!=1 or not public.startswith(('ssh-','ecdsa-','sk-')) or len(public.split())<2:
        raise ValueError('Select a valid OpenSSH private key file.')
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    created=[]
    try:
        for path,data,mode in ([(target,content,0o600)] if private else [])+[(public_target,(public+'\n').encode(),0o644)]:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
            created.append(path)
            with os.fdopen(fd,'wb') as out:
                out.write(data);out.flush();os.fsync(out.fileno())
    except Exception:
        for path in created:path.unlink(missing_ok=True)
        raise
    return str(public_target)


def matching_public_key(private_path):
    """Check the actual private key's public portion, including encrypted OpenSSH keys."""
    import base64
    import struct
    private_path=Path(private_path)
    public_path=private_path.with_name(private_path.name+'.pub')
    try:
        if not private_path.is_file() or not public_path.is_file():return False
        if private_path.stat().st_size>1024*1024 or public_path.stat().st_size>1024*1024:return False
        public=public_path.read_text().strip()
        if len(public.splitlines())!=1:return False
        expected=base64.b64decode(public.split()[1],validate=True)
        private=private_path.read_bytes()
        if private.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----'):
            data=base64.b64decode(b''.join(private.splitlines()[1:-1]),validate=True)
            magic=b'openssh-key-v1\x00'
            if not data.startswith(magic):return False
            offset=len(magic)
            def string():
                nonlocal offset
                length=struct.unpack_from('>I',data,offset)[0];offset+=4
                value=data[offset:offset+length];offset+=length
                if len(value)!=length:raise ValueError('Truncated key')
                return value
            for _ in range(3):string()  # cipher, KDF and KDF options
            count=struct.unpack_from('>I',data,offset)[0];offset+=4
            if count!=1:return False
            actual=string()
        else:
            result=subprocess.run(['ssh-keygen','-y','-f',str(private_path)],input='\n',capture_output=True,text=True,start_new_session=os.name!='nt',timeout=5)
            if result.returncode:return False
            actual=base64.b64decode(result.stdout.split()[1],validate=True)
        return actual==expected
    except (OSError,ValueError,IndexError,struct.error,subprocess.TimeoutExpired):
        return False
