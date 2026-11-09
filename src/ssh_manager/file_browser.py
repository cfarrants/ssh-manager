"""Shared terminal file-browser state and filtering, independent of its caller."""
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileBrowser:
    directory: Path = field(default_factory=lambda:Path.home())
    title: str = 'Choose File'
    description: str = 'Select a file.'
    excluded_suffixes: tuple = ()
    entries: list = field(default_factory=list)
    error: str = ''
    loading: bool = False
    show_hidden: bool = False
    filter_text: str = ''

    def list_directory(self, directory):
        folder=Path(directory).expanduser().resolve()
        entries=[]
        for path in folder.iterdir():
            try:is_dir=path.is_dir()
            except OSError:is_dir=False
            if not is_dir and path.suffix.casefold() in self.excluded_suffixes:continue
            entries.append((path.name,path,is_dir))
        entries.sort(key=lambda row:(not row[2],row[0].casefold()))
        if folder.parent!=folder:entries.insert(0,('..',folder.parent,True))
        return folder,entries

    @property
    def visible_entries(self):
        query=self.filter_text.casefold()
        return [entry for entry in self.entries
                if (entry[0]=='..' and not query) or
                (entry[0]!='..' and (self.show_hidden or not entry[0].startswith('.')) and query in entry[0].casefold())]
