"""Direct curses renderer.
Only this module owns the screen; workers return data to its asyncio loop.
"""
from __future__ import annotations
import asyncio
from contextlib import contextmanager
import curses
import datetime
import inspect
import os
from pathlib import Path
import sys
import textwrap
import time
import unicodedata
from .key_import import matching_public_key
from .controller import Form, Viewer, VIEWS, ADD_CONNECTION, ADD_KEY, IMPORT_KEY, BROWSE_KEY, FileBrowser, ProgressComplete, KeyAdmin


def safe(value):
    return ''.join(c if c.isprintable() else '?' for c in str(value))


def cell_width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def fit(text, width):
    result, used = [], 0
    for char in safe(text):
        n = cell_width(char)
        if used+n > width:
            break
        result.append(char)
        used += n
    return ''.join(result)


class Console:
    def __init__(self, manager):
        self.app = manager
        manager.ui = self
        self.win = None
        self.modal = None
        self.pending = None
        self.focus = self.caret = 0
        self.values = []
        self.offsets = {}
        self.horizontal = 0
        self.viewer_offset = 0
        self.modal_started = 0
        self.last_frame = None
        self.suspended = False
        self.filtering = False
        self.wake = None
        self._viewer_cache = None
        self.form_offset = 0
        self.key_picker = None
        self._field_values = {}
        self._active_fields = []
        self._form_source = None

    def setup(self):
        if sys.stdout.isatty():
            sys.stdout.write('\x1b]0;SSH MANAGER\x07');sys.stdout.flush()
        curses.curs_set(0)
        self.win.keypad(True)
        self.win.nodelay(True)
        if hasattr(curses, 'set_escdelay'):
            curses.set_escdelay(25)
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                background = -1
            except curses.error:
                background = curses.COLOR_BLACK
            for number, colour in ((1, curses.COLOR_CYAN), (2, curses.COLOR_RED), (3, 208 if curses.COLORS >= 256 else curses.COLOR_YELLOW), (5, curses.COLOR_GREEN), (6, curses.COLOR_WHITE), (7, 33 if curses.COLORS >= 256 else curses.COLOR_BLUE), (8, 141 if curses.COLORS >= 256 else curses.COLOR_MAGENTA)):
                curses.init_pair(number, colour, background)
            curses.init_pair(4, curses.COLOR_RED, curses.COLOR_WHITE)

    def colour(self, number):
        return curses.color_pair(number) if curses.has_colors() else 0

    def put(self, row, col, value, attr=0, width=None):
        h, w = self.win.getmaxyx()
        if not 0 <= row < h or not 0 <= col < w:
            return
        available = max(0, w-col-1)
        if width is not None:
            available = min(available, max(0, width))
        try:
            self.win.addstr(row, col, fit(value, available), attr)
        except curses.error:
            pass

    @contextmanager
    def suspend(self):
        if not self.win:
            yield
            return
        self.suspended = True
        curses.def_prog_mode()
        curses.endwin()
        try:
            yield
        finally:
            curses.reset_prog_mode()
            self.setup()
            self.win.clearok(True)
            self.suspended = False
            self.app.dirty = True

    async def show(self, modal):
        if self.modal is not None:
            raise RuntimeError('Close the current dialog before opening another.')
        self.modal = modal
        self.pending = asyncio.get_running_loop().create_future()
        self.focus = -1 if isinstance(modal, Form) and modal.tabs else 0
        if isinstance(modal,Form) and modal.default_cancel:
            self.focus=len(modal.fields)+(len(modal.secure_fields) if modal.secure_tab else 0)+1+int(modal.delete)
        self.viewer_offset = 0
        self.modal_started = time.monotonic()
        self._viewer_cache = None
        self.form_offset = 0
        self.values = [str(field[2]) for field in modal.fields+modal.secure_fields] if isinstance(modal, Form) else []
        self.caret = len(self.values[0]) if self.values else 0
        self.app.dirty = True
        if isinstance(modal,FileBrowser):
            self.load_folder(modal.directory)
        elif isinstance(modal,Form) and modal.key_list_only:
            self.open_key_picker(0)
        try:
            return await self.pending
        finally:
            if isinstance(modal, Viewer):
                modal.value = ''
            self.values.clear()
            self._field_values.clear()
            self._active_fields = []
            self._form_source = None
            self.key_picker = None
            self.modal = self.pending = None
            self._viewer_cache = None
            self.app.dirty = True

    async def show_overlay(self, modal):
        """Temporarily show a child dialog without discarding its parent form."""
        names=('modal','pending','focus','caret','values','viewer_offset','modal_started',
               '_viewer_cache','form_offset','key_picker','_field_values','_active_fields','_form_source')
        saved={name:getattr(self,name) for name in names}
        self.modal=self.pending=None
        self.key_picker=None
        self._field_values={};self._active_fields=[];self._form_source=None
        try:
            return await self.show(modal)
        finally:
            for name,value in saved.items():setattr(self,name,value)
            self.app.dirty=True

    def dismiss(self, result=None):
        if self.pending and not self.pending.done():
            self.pending.set_result(result)

    def submit_form(self, result):
        modal = self.modal
        if modal.submitting or not self.pending or self.pending.done():
            return
        if not modal.submit_handler:
            self.dismiss(result)
            return
        modal.submitting = True
        modal.error = ''
        self.app.dirty = True
        async def validate():
            try:
                await modal.submit_handler(result)
            except Exception as error:
                modal.error = str(error)
                self.focus = 0
                self.caret = len(self.values[0]) if self.values else 0
                result.clear()
            else:
                self.dismiss(result)
            finally:
                modal.submitting = False
                self.app.dirty = True
        asyncio.create_task(validate())

    def form_fields(self):
        all_fields = self.modal.fields+self.modal.secure_fields
        if self._form_source is not self.modal:
            self._field_values = {field[0]:str(field[2]) for field in all_fields}
            self._field_values.update({field[0]:value for field,value in zip(all_fields,self.values)})
            self._active_fields = all_fields
            self._form_source = self.modal
        self._field_values.update({field[0]:value for field,value in zip(self._active_fields,self.values)})
        fields = self.modal.fields+(self.modal.secure_fields if self.modal.secure_tab else [])
        if self.modal.secure_tab and {'identity','login_password'}.issubset(f[0] for f in fields):
            password=next(f for f in fields if f[0]=='login_password')
            fields.remove(password)
            fields.insert(next(i for i,f in enumerate(fields) if f[0]=='identity'),password)
        if self.modal.secure_tab and self.modal.conditional_hide:
            key,value,hidden = self.modal.conditional_hide
            if self._field_values.get(key)==value:
                hidden = set(hidden)
                fields = [field for field in fields if field[0] not in hidden]
        self.values = [self._field_values[field[0]] for field in fields]
        self._active_fields = fields
        return fields

    def open_key_picker(self, index):
        field = self.form_fields()[index][0]
        rows = [('Use default key','','')]
        if field == 'new_identity':
            rows.append(('Generate new key pair','new',''))
        list_only=self.modal.key_list_only
        browse=field=='identity' and self.modal.tabs and self.modal.secure_tab
        state = dict(field=index,rows=rows,focus=0,loading=True,error='',browse=browse)
        self.key_picker = state
        async def load():
            try:
                fields={f[0]:v for f,v in zip(self.form_fields(),self.values)}
                def available():
                    keys=[key for key in self.app.scan_keys() if matching_public_key(Path(key['path']).with_suffix(''))]
                    default=self.app.default_key(fields.get('alias',''),fields.get('hostname',''),fields.get('user',''))
                    return keys,default
                keys,default = await asyncio.to_thread(available)
                if self.key_picker is not state:
                    return
                if default:
                    rows[0]=('Default: '+Path(default).name,default,default)
                elif self.modal.key_list_only:
                    rows.clear()
                else:
                    rows[0]=('No default key found; use SSH defaults','','No verified default key pair was found')
                seen = {default} if default else set()
                for key in keys:
                    path = Path(key['path']).with_suffix('')
                    if not path.is_file() or str(path) in seen:
                        continue
                    seen.add(str(path))
                    label = path.name+(' · '+key['label'] if key.get('label') else '')
                    rows.append((label,str(path),key['fingerprint']))
                current = self.values[index]
                state['focus'] = next((i for i,row in enumerate(rows) if row[1]==current),0)
            except Exception as error:
                state['error'] = str(error)
            finally:
                rows.append(('Browse Key',BROWSE_KEY,'Use an existing private key for the initial connection only') if browse else ('Add SSH Key' if list_only else 'Import Key',IMPORT_KEY,'Browse for a private key to import'))
                state['loading'] = False
                self.app.dirty = True
        asyncio.create_task(load())

    def key_picker_key(self, key):
        state = self.key_picker
        if state.get('importing'):return
        if key in ('\x1b','\x03'):
            self.key_picker = None
            if self.modal.key_list_only:self.dismiss()
            return
        if key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_PPAGE,curses.KEY_NPAGE,curses.KEY_HOME,curses.KEY_END):
            page = max(1,self.win.getmaxyx()[0]-12) if self.win else 8
            target = state['focus']+{curses.KEY_UP:-1,curses.KEY_DOWN:1,curses.KEY_PPAGE:-page,curses.KEY_NPAGE:page}.get(key,0)
            if key==curses.KEY_HOME:target=0
            elif key==curses.KEY_END:target=len(state['rows'])-1
            state['focus'] = max(0,min(target,len(state['rows'])-1))
        elif key in ('\n','\r',curses.KEY_ENTER) and not state['loading']:
            if state['rows'][state['focus']][1] in (IMPORT_KEY,BROWSE_KEY):
                state['importing']=True
                asyncio.create_task(self.import_picker_key(state))
                return
            index = state['field']
            self.values[index] = state['rows'][state['focus']][1]
            self.focus = index+1
            self.caret = len(self.values[self.focus]) if self.focus<len(self.form_fields()) else 0
            self.key_picker = None
            if self.modal.key_list_only:self.dismiss({self.form_fields()[index][0]:self.values[index]})

    async def import_picker_key(self, state):
        try:
            if state.get('browse'):
                private=await self.show_overlay(FileBrowser(title='Browse SSH Key',description='Select a private key for the current account. It will not be imported.',excluded_suffixes=('.pub',)))
            else:
                private=await self.app.import_key_dialog(self.show_overlay)
            if private and self.key_picker is state:
                index=state['field']
                self.values[index]=private
                self.focus=index+1
                self.caret=len(self.values[self.focus]) if self.focus<len(self.form_fields()) else 0
                self.key_picker=None
                if self.modal.key_list_only:self.dismiss({self.form_fields()[index][0]:private})
        except Exception as error:
            state['error']=str(error)
        finally:
            state['importing']=False
            self.app.dirty=True

    def load_folder(self, directory):
        browser=self.modal
        if not isinstance(browser,FileBrowser) or browser.loading:return
        browser.loading=True;browser.error=''
        async def load():
            try:
                folder,entries=await asyncio.to_thread(browser.list_directory,directory)
                if self.modal is browser:
                    browser.directory=folder;browser.entries=entries;browser.filter_text="";self.focus=0
            except Exception as error:
                if self.modal is browser:browser.error='Cannot open folder: '+str(error)
            finally:
                browser.loading=False;self.app.dirty=True
        asyncio.create_task(load())

    def file_browser_key(self,key):
        browser=self.modal
        if browser.loading:return
        entries=browser.visible_entries
        count=len(entries)
        self.focus=max(0,min(self.focus,count-1))
        if key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_PPAGE,curses.KEY_NPAGE,curses.KEY_HOME,curses.KEY_END):
            page=max(1,self.win.getmaxyx()[0]-10) if self.win else 10
            target=self.focus+{curses.KEY_UP:-1,curses.KEY_DOWN:1,curses.KEY_PPAGE:-page,curses.KEY_NPAGE:page}.get(key,0)
            if key==curses.KEY_HOME:target=0
            elif key==curses.KEY_END:target=count-1
            self.focus=max(0,min(target,count-1))
        elif key in (curses.KEY_BACKSPACE,'\b','\x7f'):
            if browser.filter_text:
                browser.filter_text=browser.filter_text[:-1];self.focus=0
            else:self.load_folder(browser.directory.parent)
        elif key==curses.KEY_LEFT:
            self.load_folder(browser.directory.parent)
        elif key=='\x07':
            self.load_folder(Path.home())
        elif key=='.' and not browser.filter_text:
            browser.show_hidden=not browser.show_hidden;self.focus=0
        elif key in ('\n','\r',curses.KEY_ENTER,curses.KEY_RIGHT) and count:
            _,path,is_dir=entries[self.focus]
            if is_dir:self.load_folder(path)
            elif key!=curses.KEY_RIGHT:self.dismiss(str(path))
        elif isinstance(key,str) and key.isprintable():
            browser.filter_text+=key;self.focus=0

    def close_secret(self):
        if isinstance(self.modal, Viewer) and self.modal.secret:
            self.dismiss()

    async def run(self, win):
        self.win = win
        self.setup()
        self.app.refresh_inventory(force=True)
        loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        reader = False
        if os.name != 'nt':
            try:
                loop.add_reader(sys.stdin.fileno(), self.wake.set)
                reader = True
            except (AttributeError, NotImplementedError, OSError, ValueError):
                pass
        try:
            while self.app.is_running:
                self.wake.clear()
                for _ in range(64):
                    try:
                        key = win.get_wch()
                    except curses.error:
                        break
                    self.app.last_input = time.monotonic()
                    self.handle_key(key)
                else:
                    # Curses may have buffered more pasted input after the OS
                    # descriptor becomes empty; drain it without a polling delay.
                    self.wake.set()
                self.app.tick()
                if isinstance(self.modal, Viewer) and self.modal.secret and time.monotonic()-self.modal_started >= 30:
                    self.dismiss()
                state = (win.getmaxyx(), int(time.monotonic()*2))
                if self.app.dirty or state != self.last_frame:
                    self.draw()
                    self.app.dirty = False
                    self.last_frame = state
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout=0.25 if reader else 0.05)
                except asyncio.TimeoutError:
                    pass
        finally:
            if reader:
                loop.remove_reader(sys.stdin.fileno())
            self.app.vault.lock()
            tasks = [task for task in self.app.jobs.values() if not task.done()]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    def launch(self, name):
        if self.app.busy:
            return
        action = getattr(self.app, 'action_'+name)
        result = action()
        if inspect.iscoroutine(result):
            asyncio.create_task(result)
        self.app.dirty = True

    def cycle_page(self, reverse=False):
        app=self.app
        if app.busy:return
        app.action_view(VIEWS[(VIEWS.index(app.view)+(-1 if reverse else 1))%len(VIEWS)])
        self.horizontal=0
        self.filtering=False

    def handle_key(self, key):
        app = self.app
        app.dirty = True
        if key == curses.KEY_RESIZE:
            # Also supported by windows-curses/PDCurses.
            try:
                curses.resize_term(0, 0)
            except curses.error:
                pass
            return
        if key in ('\t',curses.KEY_BTAB):
            self.cycle_page(key==curses.KEY_BTAB)
            return
        if self.modal:
            self.modal_key(key)
            return
        if app.busy or (app.jobs.get('interaction') and not app.jobs['interaction'].done()):
            return
        if self.filtering:
            if key in ('\x1b', '\n', '\r', curses.KEY_ENTER):
                self.filtering = False
                if key == '\x1b':
                    app.filter_text = ''
                app.render_table()
            elif key in ('\b', '\x7f', curses.KEY_BACKSPACE):
                app.filter_text = app.filter_text[:-1]
                app.render_table()
            elif isinstance(key, str) and key.isprintable():
                app.filter_text += key
                app.render_table()
            return
        if key in ('q', 'Q', '\x03'):
            self.launch('quit')
        elif key in ('\n', '\r', curses.KEY_ENTER):
            self.launch('open')
        elif app.view=='accounts' and key in (curses.KEY_LEFT,curses.KEY_RIGHT,' '):
            app.toggle_key_details(False if key==curses.KEY_LEFT else True if key==curses.KEY_RIGHT else None)
        elif isinstance(key,str) and key.lower() in ('c','k','a'):
            app.action_view({'c':'connections','k':'accounts','a':'activity'}[key.lower()])
            self.horizontal=0
        elif key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE, curses.KEY_NPAGE, curses.KEY_HOME, curses.KEY_END):
            page = self.table_page(self.win.getmaxyx()[0]) if self.win else 10
            target = app.cursor + {curses.KEY_UP:-1, curses.KEY_DOWN:1, curses.KEY_PPAGE:-page, curses.KEY_NPAGE:page}.get(key, 0)
            if key == curses.KEY_HOME:
                target = 0
            elif key == curses.KEY_END:
                target = len(app.rows)-1
            elif app.view in ('connections','accounts') and app.rows and key in (curses.KEY_UP,curses.KEY_DOWN):
                target %= len(app.rows)
            app.select(target)
        elif key == '/':
            self.filtering = True
        elif key == '\x1b':
            app.filter_text = ''
            app.render_table()
        elif key in ('[', ']'):
            self.horizontal = max(0, self.horizontal + (-12 if key == '[' else 12))
        elif app.view == 'connections' and key in ('a', 'd', 'e', 'i'):
            return
        elif key == 'X':
            self.launch('editor')
        elif key == 'x' and app.view == 'connections':
            if app.row_id() != ADD_CONNECTION:
                self.launch('edit')
        elif key in {'a','e','d','r','i','o','n','k','u','l','p','x','s'}:
            self.launch({'a':'add','e':'edit','d':'delete','r':'refresh','i':'inspect','o':'operations','n':'notes','k':'new_key','u':'unlock','l':'lock','p':'pause','x':'editor','s':'settings'}[key])

    def modal_key(self, key):
        if isinstance(self.modal,ProgressComplete):
            if key in ('\n','\r',curses.KEY_ENTER,'\x1b'):self.dismiss()
            return
        if key in ('\t',curses.KEY_BTAB):
            self.cycle_page(key==curses.KEY_BTAB)
            return
        if isinstance(self.modal,Form) and self.modal.submitting:
            return
        if self.key_picker:
            self.key_picker_key(key)
            return
        if key=='\x1b' and isinstance(self.modal,FileBrowser) and self.modal.filter_text:
            self.modal.filter_text='';self.focus=0
            return
        if key in ('\x1b', '\x03'):
            self.dismiss()
            return
        if isinstance(self.modal,FileBrowser):
            self.file_browser_key(key)
            return
        if isinstance(self.modal, Viewer):
            if key in ('\n','\r',curses.KEY_ENTER):
                self.dismiss()
            elif key in (curses.KEY_DOWN,curses.KEY_UP,curses.KEY_NPAGE,curses.KEY_PPAGE):
                page = max(1, self.win.getmaxyx()[0]-10) if self.win else 10
                self.viewer_offset = max(0, self.viewer_offset+{curses.KEY_DOWN:1,curses.KEY_UP:-1,curses.KEY_NPAGE:page,curses.KEY_PPAGE:-page}[key])
            elif key == curses.KEY_HOME:
                self.viewer_offset = 0
            elif key == curses.KEY_END:
                self.viewer_offset = 10**9
            return
        if isinstance(self.modal,KeyAdmin):
            panel=self.modal
            if panel.loading:return
            count=len(panel.keys)+1
            if key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_HOME,curses.KEY_END):
                self.focus=(self.focus+(-1 if key==curses.KEY_UP else 1))%count
                if key==curses.KEY_HOME:self.focus=0
                elif key==curses.KEY_END:self.focus=count-1
            elif key in ('a','A'):self.dismiss(('add',None))
            elif key in ('r','R','c','C','\n','\r',curses.KEY_ENTER):
                if self.focus>=len(panel.keys):self.dismiss(('add',None))
                elif key in ('r','R'):self.dismiss(('revoke',panel.keys[self.focus]))
                elif key in ('c','C'):self.dismiss(('cycle',panel.keys[self.focus]))
            elif key==curses.KEY_F5:self.dismiss(('refresh',None))
            return
        fields = self.form_fields()
        n = len(fields)
        buttons = [self.modal.submit]+(['Delete'] if self.modal.delete else [])+[self.modal.cancel]
        if self.modal.tabs and self.focus == -1:
            if key in (curses.KEY_LEFT,curses.KEY_RIGHT,' '):
                self.modal.secure_tab = not self.modal.secure_tab
            elif key in ('\n','\r',curses.KEY_ENTER,curses.KEY_DOWN):
                self.focus = 0
                self.caret = len(self.values[0])
            elif key in (curses.KEY_UP,):
                self.focus = n+len(buttons)-1
            return
        if key in (curses.KEY_UP, curses.KEY_DOWN):
            step = -1 if key in (curses.KEY_UP,) else 1
            self.focus = (self.focus+step+1) % (n+len(buttons)+1)-1 if self.modal.tabs else (self.focus+step) % (n+len(buttons))
            self.caret = len(self.values[self.focus]) if 0 <= self.focus < n else 0
        elif key in ('\n','\r',curses.KEY_ENTER):
            if self.focus < n:
                if fields[self.focus][0] in self.modal.key_pickers and fields[self.focus][0] not in self.modal.read_only:
                    self.open_key_picker(self.focus)
                    return
                self.focus += 1
                self.caret = len(self.values[self.focus]) if self.focus < n else 0
            elif self.focus == n:
                result = {field[0]: value for field, value in zip(fields, self.values)}
                if self.modal.tabs:
                    result['_secure'] = self.modal.secure_tab
                self.submit_form(result)
            elif buttons[self.focus-n] == 'Delete':
                self.dismiss({'_action':'delete'})
            else:
                self.dismiss()
        elif self.focus >= n and key in (curses.KEY_LEFT,curses.KEY_RIGHT):
            self.focus = n+(self.focus-n+(-1 if key == curses.KEY_LEFT else 1)) % len(buttons)
        elif self.focus < n:
            if fields[self.focus][0] in self.modal.read_only:return
            value = self.values[self.focus]
            options = self.modal.choices.get(fields[self.focus][0])
            if options:
                if key in (curses.KEY_LEFT,curses.KEY_RIGHT,' '):
                    self.values[self.focus] = options[(options.index(value)+(-1 if key==curses.KEY_LEFT else 1)) % len(options)]
                return
            if key in ('\b','\x7f',curses.KEY_BACKSPACE) and self.caret:
                self.values[self.focus] = value[:self.caret-1]+value[self.caret:]
                self.caret -= 1
            elif key == curses.KEY_DC:
                self.values[self.focus] = value[:self.caret]+value[self.caret+1:]
            elif key == curses.KEY_LEFT:
                self.caret = max(0,self.caret-1)
            elif key == curses.KEY_RIGHT:
                self.caret = min(len(value),self.caret+1)
            elif key in (curses.KEY_HOME,'\x01'):
                self.caret = 0
            elif key in (curses.KEY_END,'\x05'):
                self.caret = len(value)
            elif key == '\x15':
                self.values[self.focus] = value[self.caret:]
                self.caret = 0
            elif isinstance(key,str) and key.isprintable() and len(value) < 8192:
                self.values[self.focus] = value[:self.caret]+key+value[self.caret:]
                self.caret += len(key)

    def draw(self):
        self.win.erase()
        h, w = self.win.getmaxyx()
        if h < 16 or w < 45:
            self.put(0,0,'ssh-manager/  Enlarge terminal to at least 45 × 16.')
            self.put(2,0,'q quit')
            self.win.refresh()
            return
        app = self.app
        cyan = curses.A_BOLD | self.colour(1)
        content_top=self.content_top(h,w)
        self.put(1,0,' '*w,curses.A_REVERSE)
        self.put(1,max(0,(w-len('SSH MANAGER'))//2),'SSH MANAGER',curses.A_REVERSE)
        self.put(content_top-3,2,'─'*(w-4))
        x = 2
        for name in VIEWS:
            text='Keys + Accounts' if name=='accounts' else name.title()
            attr=self.colour(6)|curses.A_REVERSE|curses.A_BOLD if app.view==name else cyan
            self.put(content_top-2,x,' '+text+' ',attr)
            self.put(content_top-2,x+1,text[0],attr|curses.A_UNDERLINE)
            x+=len(text)+5
        self.put(content_top-1,2,'─'*(w-4))
        host = app.host()
        if app.view=='accounts':
            self.draw_accounts(h,w)
        else:
            self.draw_table(h,w)
        if self.filtering:
            prompt = 'Filter: '+app.filter_text
        elif app.view=='accounts':
            row=app.account_rows.get(app.row_id(),{})
            prompt = f"{row['user']}@{row['alias']}" if row.get('kind')=='account' else Path(app.row_id()).name if row.get('kind')=='key' else 'Generate New Key' if app.row_id()==ADD_KEY else 'Import Key' if app.row_id()==IMPORT_KEY else ''
        elif app.view == 'connections':
            prompt = '+ Add Connection' if app.row_id() == ADD_CONNECTION else f'{host.user}@{host.alias}' if host else ''
        else:
            prompt = app.message
        self.put(h-3,1,' '*(w-2),curses.A_REVERSE)
        self.put(h-3,2,'> '+prompt,curses.A_REVERSE)
        cursor_x = min(w-3,4+cell_width(safe(prompt)))
        self.put(h-3,cursor_x,' ',curses.A_NORMAL if int(time.monotonic()*2)%2 == 0 else curses.A_REVERSE)
        clock = 'LIVE | '+datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        if w < 110:
            clock = 'LIVE | '+datetime.datetime.now().strftime('%H:%M:%S')
        clock_x = max(2,w-len(clock)-2)
        hint = {'connections':'↑↓ select | ↵ connect | x edit | o key admin', 'domains':'a/d domain | r DNS | i inspect | ↵ details', 'users':'i inspect | o key admin | ↵ keys', 'keys':'k new | r scan | ↵ public key | o deploy', 'vault':'u/l open/hide | a/d save/remove | ↵ reveal', 'accounts':'↑↓ select | ←→/Space key details | ↵ open/add | d delete key | Tab pages', 'activity':'↑↓ select | ↵ full event | / filter'}[app.view]
        if 'Tab' not in hint:hint+=' | Tab pages'
        self.put(h-2,2,hint,width=max(0,clock_x-4))
        self.put(h-2,clock_x,clock)
        self.put(h-2,clock_x,'LIVE',curses.A_BOLD|self.colour(2))
        if self.modal and not isinstance(self.modal,ProgressComplete):
            if not (isinstance(self.modal,Form) and self.modal.key_list_only):self.draw_modal(h,w)
            if self.key_picker:
                self.draw_key_picker(h,w)
        elif app.busy and (getattr(app,'secure_setup_running',False) or getattr(app,'key_setup_running',False)):
            key_setup=getattr(app,'key_setup_running',False)
            actions=getattr(app,'setup_completed',[]) if key_setup else []
            top,left,height,width = self.box(h,w,13+len(actions) if key_setup else 10,(getattr(app,'setup_title','') or 'Authorise SSH Key') if key_setup else 'Add new Server and Secure')
            error=getattr(app,'setup_error','')
            for index,line in enumerate(textwrap.wrap(safe(error or app.message),width-6)[:3]):
                self.put(top+3+index,left+3,line,self.colour(2) if error else self.colour(6),width=width-6)
            stage = getattr(app,'setup_stage',0)
            total = getattr(app,'setup_stages',6)
            size = max(8,width-24)
            # A moving segment shows ongoing work without inventing a percentage.
            countdown=getattr(app,'setup_countdown',None)
            position = int(time.monotonic()*8) % (size+4)-4
            bar = ''.join('━' if position <= i < position+4 else '─' for i in range(size))
            label=f'Stage {max(1,stage)}/{total}'
            if isinstance(self.modal,ProgressComplete):bar='━'*size;label='Complete'
            if countdown is not None:
                filled=round(size*max(0,min(30,30-countdown))/30)
                bar='━'*filled+'─'*(size-filled)
                label=f'Rollback in {countdown}s' if countdown else 'Rolling back…'
            self.put(top+6 if key_setup else top+height-4,left+3,f'[{bar}] {label}',self.colour(2) if error else self.colour(1),width=width-6)
            if key_setup:
                for index,action in enumerate(actions[-max(1,height-12):]):
                    self.put(top+8+index,left+3,'✓ '+action,self.colour(5),width=width-6)
            if isinstance(self.modal,ProgressComplete):
                button_width=min(23,width-6)
                self.button(top+height-4,left+(width-button_width)//2,'Close',True,button_width)
            else:
                self.put(top+height-2,left+3,'Setup in progress · keep this window open',width=width-6)
        self.win.refresh()

    def draw_accounts(self,h,w):
        app=self.app
        top=self.content_top(h,w)
        available=h-top-4
        key_height=max(4,available//2)
        sections=[('SSH Keys',top,key_height,'key',ADD_KEY),('User Accounts',top+key_height,available-key_height,'account',None)]
        for title,top,height,kind,action in sections:
            if height<3:continue
            left=2;width=w-4
            self.put(top,left,'┌─ '+title+' '+'─'*max(0,width-len(title)-5)+'┐',self.colour(6))
            self.put(top+height-1,left,'└'+'─'*(width-2)+'┘',self.colour(6))
            for y in range(top+1,top+height-1):
                self.put(y,left,'│',self.colour(6));self.put(y,left+width-1,'│',self.colour(6))
            lines=[]
            for key,cells in app.rows:
                row=app.account_rows.get(key,{})
                is_action=key==action or (kind=='key' and key==IMPORT_KEY)
                if not is_action and row.get('kind')!=kind:continue
                lines.append((key,cells[0] if is_action else ('▾ ' if key in app.expanded_keys else '▸ ')+cells[0] if kind=='key' else fit(cells[0],max(8,(width-7)//3)).ljust(max(8,(width-7)//3))+' '+fit(cells[1],max(8,(width-7)//3)).ljust(max(8,(width-7)//3))+' '+cells[2],False))
                if kind=='key' and key in app.expanded_keys and row:
                    details=['Fingerprint: '+row['item']['fingerprint'],'Attached accounts: '+(', '.join(row['deployments']) or 'No known attachments; inspect servers to discover authorised keys.')]
                    for detail in details:
                        for line in textwrap.wrap(detail,max(1,width-9)):
                            lines.append((key,'    '+line,True))
            page=max(1,height-2)
            selected=next((i for i,(key,_,detail) in enumerate(lines) if key==app.row_id() and not detail),None)
            offset=self.offsets.get('accounts-'+kind,0)
            if selected is not None:
                if selected<offset:offset=selected
                elif selected>=offset+page:offset=selected-page+1
                if kind=='key' and app.row_id() in app.expanded_keys:
                    end=selected
                    while end+1<len(lines) and lines[end+1][0]==app.row_id():end+=1
                    if end-selected<page:offset=max(0,end-page+1) if end>=offset+page else offset
            offset=min(max(0,offset),max(0,len(lines)-page))
            self.offsets['accounts-'+kind]=offset
            for index,(key,text,detail) in enumerate(lines[offset:offset+page]):
                attr=curses.A_REVERSE if key==app.row_id() and not detail else self.colour(8) if detail else self.colour(1) if key in (action,IMPORT_KEY) else self.colour(6)
                self.put(top+1+index,left+2,text,attr,width=width-5)
            self.scrollbar(top+1,left+width-2,page,offset,page,len(lines))

    def content_top(self,h,w):
        return 5

    def table_page(self, height):
        width=self.win.getmaxyx()[1] if self.win else 120
        gap=1 if self.app.view=='connections' and len(self.app.rows)>1 else 0
        return max(1,height-self.content_top(height,width)-5-gap)

    def draw_table(self, h, w):
        app = self.app
        caps = {'connections':[26,36,18,5,10,12], 'domains':[42,22,16,48,25], 'users':[22,8,24,32,16,25], 'keys':[35,52,35,60], 'vault':[24,30,25], 'activity':[25,24,26,90]}[app.view]
        widths = [max(len(header), min(cap, max((cell_width(cells[i]) for _, cells in app.rows),default=0))) for i,(header,cap) in enumerate(zip(app.headers,caps))]
        def line(cells):
            return '  '.join(fit(cell,width)+' '*max(0,width-cell_width(fit(cell,width))) for cell,width in zip(cells,widths))
        header = line(app.headers)
        max_scroll = max(0,cell_width(header)-(w-4))
        self.horizontal = min(self.horizontal,max_scroll)
        header_row = self.content_top(h,w)
        self.put(header_row,2,header[self.horizontal:],curses.A_BOLD|self.colour(5))
        self.put(header_row+1,2,'─'*(w-4))
        page = self.table_page(h)
        offset = self.offsets.get(app.view,0)
        offset = max(0,min(offset,app.cursor))
        offset = max(offset,app.cursor-page+1)
        self.offsets[app.view] = offset
        for visual, (index, (_, cells)) in enumerate(enumerate(app.rows[offset:offset+page],offset)):
            attr = curses.A_REVERSE if index == app.cursor else 0
            if app.rows[index][0] == ADD_CONNECTION:
                attr = curses.A_REVERSE if index == app.cursor else self.colour(1)
            elif not attr and app.view == 'connections':
                attr = self.colour(5 if cells[-1]=='ONLINE' else 2 if cells[-1]=='OFFLINE' else 3)
            if not attr and app.view == 'domains':
                attr = self.colour(5 if cells[2]=='POINTS HERE' else 3)
            gap=1 if app.view=='connections' and app.rows[index][0]==ADD_CONNECTION and len(app.rows)>1 else 0
            self.put(header_row+2+visual+gap,2,line(cells)[self.horizontal:],attr)
        if not app.rows:
            message = 'Saved passwords hidden · u open' if app.view=='vault' and not app.vault.cipher else 'No matching rows.' if app.filter_text else 'No records yet.'
            self.put(header_row+3,2,message)

    def box(self,h,w,height,title,top_aligned=False):
        width = min(82,w-4)
        height = min(height,h-2)
        left,top = (w-width)//2,1 if top_aligned else (h-height)//2
        border = curses.A_BOLD|self.colour(2)
        for row in range(height):
            self.put(top+row,left,' '*width)
        self.put(top,left,'┌'+'─'*(width-2)+'┐',border)
        self.put(top+height-1,left,'└'+'─'*(width-2)+'┘',border)
        for row in range(1,height-1):
            self.put(top+row,left,'│',border)
            self.put(top+row,left+width-1,'│',border)
        title = fit(title,width-6)
        self.put(top+1,left+(width-cell_width(title))//2,title,curses.A_BOLD|self.colour(6))
        self.put(top+2,left,'├'+'─'*(width-2)+'┤',border)
        return top,left,height,width

    def button(self,row,col,label,focused,width):
        tl,tr,bl,br,horizontal,vertical = ('╔','╗','╚','╝','═','║') if focused else ('┌','┐','└','┘','─','│')
        attr = self.colour(6)|(curses.A_BOLD if focused else 0)
        self.put(row,col,tl+horizontal*(width-2)+tr,attr)
        self.put(row+1,col,vertical+fit(label,width-2).center(width-2)+vertical,attr)
        self.put(row+2,col,bl+horizontal*(width-2)+br,attr)

    def scrollbar(self, row, col, height, offset, visible, total):
        """A small position indicator, drawn only when content overflows."""
        if total <= visible or height < 3:
            return
        offset = max(0, min(offset, total-visible))
        self.put(row,col,'↑' if offset else '─',self.colour(1))
        self.put(row+height-1,col,'↓' if offset+visible < total else '─',self.colour(1))
        track = height-2
        thumb = max(1, round(track*visible/total))
        start = round((track-thumb)*offset/(total-visible))
        for index in range(track):
            active = start <= index < start+thumb
            self.put(row+1+index,col,'█' if active else '│',self.colour(1) if active else self.colour(6))

    def grouped_rows(self, fields):
        rows = []
        group = ''
        sections = self.modal.existing_sections if self.modal.tabs and not self.modal.secure_tab and self.modal.existing_sections else self.modal.sections
        for index,(key,*_) in enumerate(fields):
            if key in sections and sections[key] != group:
                if group:
                    rows.append(('close',group,None))
                group = sections[key]
                rows.append(('open',group,None))
            rows.extend([('label',group,index),('input',group,index)])
        if group:
            rows.append(('close',group,None))
        return rows

    def draw_grouped_fields(self, fields, rows, start, left, height, width):
        page = max(1,height)
        offset = min(self.form_offset,max(0,len(rows)-page))
        if self.focus == -1:
            offset = 0
        elif self.focus >= len(fields):
            offset = max(0,len(rows)-page)
        else:
            target = next(i for i,row in enumerate(rows) if row[0]=='label' and row[2]==self.focus)
            if target < offset:
                offset = target-1 if target and rows[target-1][0]=='open' else target
            offset = max(offset,target+2-page)
        self.form_offset = max(0,offset)
        for visual,(kind,group,index) in enumerate(rows[offset:offset+page]):
            y = start+visual
            border_width = width-4
            if kind == 'open':
                title = fit(' '+group+' ',border_width-2)
                self.put(y,left+2,'┌'+title+'─'*(border_width-2-cell_width(title))+'┐',self.colour(6))
                continue
            if kind == 'close':
                self.put(y,left+2,'└'+'─'*(border_width-2)+'┘',self.colour(6))
                continue
            if group:
                self.put(y,left+2,'│',self.colour(6))
                self.put(y,left+width-3,'│',self.colour(6))
            key,label,_,secret = fields[index]
            if key=='user' and self.modal.secure_tab:
                label = 'Current Username'
            x = left+4 if group else left+3
            available = width-9 if group else width-6
            if kind=='label':
                self.put(y,x,label,self.colour(5),width=available)
                continue
            shown = '•'*len(self.values[index]) if secret else safe(self.values[index])
            if key in self.modal.key_pickers and not shown:
                shown = self.modal.placeholders.get(key,'Enter choose key')
            if key in self.modal.choices:
                shown = '‹ '+shown+' ›'
            active = self.focus==index
            input_width = max(1,available-2)
            begin = max(0,self.caret-input_width+1) if active else 0
            self.put(y,x,'> '+shown[begin:begin+input_width].ljust(input_width),curses.A_REVERSE if active else self.colour(6),width=available)
            if active and key not in self.modal.read_only:
                pos = min(x+available-1,x+2+cell_width(shown[begin:self.caret]))
                self.put(y,pos,shown[self.caret:self.caret+1] or ' ',curses.A_NORMAL if int(time.monotonic()*2)%2==0 else curses.A_REVERSE)
        self.scrollbar(start,left+width-2,page,self.form_offset,page,len(rows))

    def draw_key_picker(self,h,w):
        state = self.key_picker
        top,left,height,width = self.box(h,w,min(22,h-2),'Available SSH Keys')
        page = max(1,height-7)
        offset = max(0,state['focus']-page+1)
        for visual,(index,(label,path,fingerprint)) in enumerate(enumerate(state['rows'][offset:offset+page],offset)):
            attr = self.colour(8)|curses.A_BOLD if path in (IMPORT_KEY,BROWSE_KEY) else self.colour(6)
            if index==state['focus']:attr |= curses.A_REVERSE
            self.put(top+3+visual,left+3,label,attr,width=width-6)
        self.scrollbar(top+3,left+width-2,page,offset,page,len(state['rows']))
        selected = state['rows'][state['focus']]
        self.put(top+height-3,left+3,'Loading keys…' if state['loading'] else state['error'] or selected[2] or selected[1],width=width-6)
        self.put(top+height-2,left+3,'↑↓ select · ↵ use key · Esc back',width=width-6)

    def draw_modal(self,h,w):
        modal = self.modal
        if isinstance(modal,FileBrowser):
            top,left,height,width=self.box(h,w,min(26,h-2),modal.title)
            self.put(top+3,left+3,str(modal.directory),self.colour(1),width=width-6)
            self.put(top+4,left+3,'Hidden files: '+('shown' if modal.show_hidden else 'hidden')+' · . toggle',self.colour(8),width=width-6)
            entries=modal.visible_entries
            self.focus=max(0,min(self.focus,len(entries)-1))
            selected=str(entries[self.focus][1]) if entries else str(modal.directory)
            bar_lines=textwrap.wrap(safe('Search > '+(modal.filter_text or selected)),max(1,width-7),replace_whitespace=False,drop_whitespace=False) or ['Search > ']
            bar_lines=bar_lines[-max(1,height-11):]
            page=max(1,height-9-len(bar_lines))
            offset=max(0,self.focus-page+1)
            for index,(name,_,is_dir) in enumerate(entries[offset:offset+page],offset):
                self.put(top+5+index-offset,left+3,('[DIR] ' if is_dir and name!='..' else '' if name=='..' else '      ')+name,curses.A_REVERSE if index==self.focus else self.colour(1) if is_dir else self.colour(6),width=width-6)
            self.scrollbar(top+5,left+width-2,page,offset,page,len(entries))
            if not entries and not modal.loading:self.put(top+5,left+3,"No matching files or folders.",width=width-6)
            status='Loading…' if modal.loading else modal.error or modal.description
            for i,line in enumerate(textwrap.wrap(safe(status),max(1,width-6))[:2]):
                self.put(top+height-4+i,left+3,line,self.colour(3) if modal.error else self.colour(6),width=width-6)
            for index,line in enumerate(bar_lines):
                self.put(top+height-4-len(bar_lines)+index,left+3,line,curses.A_REVERSE,width=width-6)
            cursor=left+3+cell_width(bar_lines[-1])
            self.put(top+height-5,cursor,' ',curses.A_NORMAL if int(time.monotonic()*2)%2==0 else curses.A_REVERSE)
            self.put(top+height-2,left+3,'↵ open/use · ← parent · . hidden · Ctrl+G home · Esc clear/back',width=width-6)
        elif isinstance(modal,Viewer):
            content_width = max(1,min(82,w-4)-6)
            compact_lines = sum(max(1,len(textwrap.wrap(safe(line),content_width))) for line in modal.value.splitlines())
            top,left,height,width = self.box(h,w,compact_lines+6 if modal.compact else min(28,h-2),modal.title)
            cache_key = (width,modal.value)
            if not self._viewer_cache or self._viewer_cache[0] != cache_key:
                lines = []
                for line in modal.value.splitlines():
                    lines.extend(textwrap.wrap(safe(line.expandtabs(4)),max(1,width-6),replace_whitespace=False,drop_whitespace=False) or [''])
                self._viewer_cache = (cache_key,lines)
            lines = self._viewer_cache[1]
            page = max(1,height-6)
            self.viewer_offset = min(self.viewer_offset,max(0,len(lines)-page))
            for index,line in enumerate(lines[self.viewer_offset:self.viewer_offset+page]):
                self.put(top+3+index,left+3,line,width=width-6)
            self.scrollbar(top+3,left+width-2,page,self.viewer_offset,page,len(lines))
            hint = '↵ continue · Esc back' if len(lines)<=page else '↑↓/PgUp/PgDn scroll · ↵/Esc back'
            if modal.secret:
                hint = f'Hides in {max(0,30-int(time.monotonic()-self.modal_started))}s · Esc hide now'
            self.put(top+height-2,left+3,hint,width=width-6)
        elif isinstance(modal,KeyAdmin):
            top,left,height,width=self.box(h,w,min(24,h-2),'Key Admin')
            self.put(top+3,left+3,modal.account,self.colour(1),width=width-6)
            rows=[(key['label']+' · '+(Path(key['local_private']).name if key.get('local_private') else 'NO LOCAL PRIVATE KEY')) for key in modal.keys]+['+ Add SSH Key']
            page=max(1,height-9)
            self.focus=max(0,min(self.focus,len(rows)-1))
            offset=max(0,self.focus-page+1)
            for i,text in enumerate(rows[offset:offset+page],offset):
                self.put(top+5+i-offset,left+3,text,curses.A_REVERSE if i==self.focus else self.colour(1) if i==len(modal.keys) else self.colour(6),width=width-6)
            self.scrollbar(top+5,left+width-2,page,offset,page,len(rows))
            status='Connecting and reading authorised keys…' if modal.loading else modal.error or (modal.keys[self.focus]['fingerprint'] if self.focus<len(modal.keys) else 'Choose a local key or browse to add one.')
            for i,line in enumerate(textwrap.wrap(safe(status),max(1,width-6))[:2]):
                self.put(top+height-4+i,left+3,line,self.colour(2) if modal.error else self.colour(6),width=width-6)
            self.put(top+height-2,left+3,'↑↓ select | r revoke | c cycle | a add | F5 refresh | Esc close',width=width-6)
        else:
            fields = self.form_fields()
            help_lines = textwrap.wrap(safe(modal.help_text.replace('\n',' ')),max(1,min(76,w-10)))[:1 if modal.tabs else 3]
            if modal.overview:
                help_lines = [part for line in modal.help_text.splitlines() for part in (textwrap.wrap(safe(line),max(1,min(76,w-10))) or [''])]
            spacing = 2 if modal.tabs else 3
            grouped = self.grouped_rows(fields) if modal.sections else []
            status_rows = 2 if modal.submit_handler or modal.error else 0
            desired = (9+len(help_lines)+len(grouped) if grouped else 10+len(help_lines)+len(fields)*spacing)+status_rows
            top,left,height,width = self.box(h,w,desired,'' if modal.tabs else modal.title,top_aligned=modal.tabs)
            if modal.tabs:
                labels = ['Add Existing Connection','Add new Server and Secure'] if width>=66 else ['Existing Connection','New Server & Secure']
                tab_width = (width-7)//2
                for index,label in enumerate(labels):
                    attr = self.colour(1)|curses.A_BOLD if index==int(modal.secure_tab) else self.colour(6)
                    if self.focus==-1 and index==int(modal.secure_tab):attr |= curses.A_REVERSE
                    self.put(top+1,left+3+index*(tab_width+1),label,attr,width=tab_width)
            for i,line in enumerate(help_lines):
                colour=next((colour for source,colour in modal.highlights.items() if line and line in source),modal.text_colour if modal.text_colour!=6 else 8 if modal.overview and i%2==0 else 6)
                self.put(top+3+i,left+3,line,self.colour(colour),width=width-6)
            start = top+(3 if grouped else 4)+len(help_lines)
            available = max(1,(top+height-6-status_rows-start)//spacing)
            field_focus = max(0,min(self.focus,len(fields)-1))
            first = max(0,field_focus-available+1)
            for index in ([] if grouped else range(first,min(len(fields),first+available))):
                key,label,_,secret = fields[index]
                y = start+(index-first)*spacing
                self.put(y,left+3,label,self.colour(5),width=width-6)
                shown = '•'*len(self.values[index]) if secret else safe(self.values[index])
                if key in modal.choices:shown = '‹ '+shown+' ›'
                active = self.focus==index
                input_width = max(1,width-10)
                begin = max(0,self.caret-input_width+1) if active else 0
                attr = curses.A_REVERSE if active else self.colour(6)
                self.put(y+1,left+3,'> '+shown[begin:begin+input_width].ljust(input_width),attr,width=width-6)
                if active and key not in self.modal.read_only:
                    pos = min(left+width-4,left+5+cell_width(shown[begin:self.caret]))
                    char = shown[self.caret:self.caret+1] or ' '
                    self.put(y+1,pos,char,curses.A_NORMAL if int(time.monotonic()*2)%2==0 else curses.A_REVERSE)
            if grouped:
                self.draw_grouped_fields(fields,grouped,start,left,top+height-6-status_rows-start,width)
            else:
                self.scrollbar(start,left+width-2,available*spacing,first,available,len(fields))
            if status_rows:
                status = modal.submit_status if modal.submitting else modal.error
                for index,line in enumerate(textwrap.wrap(safe(status),max(1,width-6))[:status_rows]):
                    self.put(top+height-6-status_rows+index,left+3,line,self.colour(3),width=width-6)
            buttons = [modal.submit]+(['Delete'] if modal.delete else [])+[modal.cancel]
            button_width = min(23,max(8,(width-8-3*(len(buttons)-1))//len(buttons)))
            x = left+(width-(button_width*len(buttons)+3*(len(buttons)-1)))//2
            for index,label in enumerate(buttons):
                self.button(top+height-6,x+index*(button_width+3),'Set Up' if index==0 and modal.secure_tab else label,self.focus==len(fields)+index,button_width)
            hint = '↑↓ fields · ←→ edit/select · ↵ next/confirm · Esc cancel'
            if modal.overview:
                hint = f'←→ select · ↵ confirm · Esc {modal.cancel.lower()}'
            if 0 <= self.focus < len(fields) and fields[self.focus][0] in modal.key_pickers:
                hint = '↵ choose key · ↓ next field · Esc cancel'
            self.put(top+height-2,left+3,hint,width=width-6)
