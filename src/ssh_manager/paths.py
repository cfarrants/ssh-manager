"""Platform data location and one-time migration from the previous app name."""
import os
from pathlib import Path
import sys


def data_path():
    if sys.platform == 'darwin':
        parent=Path.home()/'Library'/'Application Support'
    elif sys.platform == 'win32':
        parent=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData'/'Local')))
    else:
        parent=Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local'/'share')))
    current=parent/'ssh-manager'
    legacy=parent/'server-manager'
    if not current.exists() and legacy.exists():
        legacy.rename(current)
    return current
