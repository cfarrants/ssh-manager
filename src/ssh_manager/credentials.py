"""OS-backed key storage only: never a plaintext or file-based fallback."""
import hmac
import keyring

SERVICE = 'ssh-manager.vault'


class SecureStorageError(ValueError):
    pass


def _select_backend():
    backend=keyring.get_keyring()
    candidates=getattr(backend,'backends',[backend])
    allowed={'keyring.backends.macOS','keyring.backends.Windows','keyring.backends.SecretService','keyring.backends.kwallet'}
    for candidate in candidates:
        if type(candidate).__module__ in allowed and candidate.priority>0:
            return candidate
    raise SecureStorageError('No supported OS credential store is available. Configure Keychain, Windows Credential Manager or Linux Secret Service/KWallet. Password storage is disabled; no insecure fallback is used.')


def _backend():
    try:return _select_backend()
    except SecureStorageError:raise
    except Exception:raise SecureStorageError('The OS credential store is unavailable. Saved passwords were not changed.') from None


def get_key(key_id):
    try:value=_backend().get_password(SERVICE,key_id)
    except SecureStorageError:raise
    except Exception:raise SecureStorageError('The OS credential store denied access or is locked. Saved passwords were not changed.') from None
    if not value:
        raise SecureStorageError('The vault encryption key is missing from the OS credential store. The vault was not overwritten. Restore the matching credential-store backup to recover it.')
    try:return value.encode('ascii')
    except UnicodeError:raise SecureStorageError('The OS-stored vault key is invalid. The vault was not changed.') from None


def store_key(key_id,key):
    backend=_backend()
    try:
        # Never overwrite a key associated with an existing vault.
        if backend.get_password(SERVICE,key_id) is not None:
            raise SecureStorageError('A vault key identifier already exists. Nothing was overwritten.')
        backend.set_password(SERVICE,key_id,key.decode('ascii'))
        saved=backend.get_password(SERVICE,key_id)
        if not saved or not hmac.compare_digest(saved,key.decode('ascii')):
            raise SecureStorageError('The OS credential store could not verify the saved key. The vault was not changed.')
    except SecureStorageError:raise
    except Exception:raise SecureStorageError('The OS credential store could not save the encryption key. The vault was not changed.') from None
