"""Support for natty IDE like features."""
from __future__ import annotations

from typing import Dict, Any, Tuple, Union, Optional, Literal, List, Iterator
from typing import ClassVar

from functools import partial
from pathlib import Path
import itertools
import traceback
import weakref

from vpe import wrappers
from vpe import common
from vpe import core
from vpe import channels
from vpe import mapping
from vpe import vim
import vpe

FindDirection = Literal[-1, 0, 1]
Buffer = wrappers.Buffer
Struct = wrappers.Struct

uid_source = itertools.count(start=1)
log_protocol = False


class Message:
    """Generic message."""
    # pylint: disable=too-few-public-methods
    req_counter: Iterator[int] = itertools.count(1)
    code: ClassVar[str] = ''

    def __init__(self, parameters: Optional[dict] = None):
        self.req_number = next(self.req_counter)
        self.parameters = parameters or {}

    def encode(self):
        """Encode into a form quitable for a JSON channel."""
        return [self.req_number, self.code, self.parameters]


class QuitMessage(Message):
    """Request for the server to quit."""
    # pylint: disable=too-few-public-methods
    code: ClassVar[str] = 'quit'


class PingMessage(Message):
    """Keep-alive ping."""
    # pylint: disable=too-few-public-methods
    code: ClassVar[str] = 'ping'
    ping_count: ClassVar[Iterator[int]] = itertools.count()

    def __init__(self):
        self.count = next(self.ping_count)
        super().__init__({'count': self.count})


class AddFileMessage(Message):
    """Request to add a quality checked file."""
    # pylint: disable=too-few-public-methods
    code: ClassVar[str] = 'add_file'

    def __init__(self, path: str, type_name: str):
        abs_path = str(Path(path).expanduser().resolve())
        super().__init__({'path': abs_path, 'type_name': type_name})


class RemoveFileMessage(Message):
    """Request to remove a quality checked file."""
    # pylint: disable=too-few-public-methods
    code: ClassVar[str] = 'remove_file'

    def __init__(self, path: str, type_name: str):
        abs_path = str(Path(path).expanduser().resolve())
        super().__init__({'path': abs_path, 'type_name': type_name})


def enabled_types(info):
    """Get a list of the enable report types.

    :info: Struct
    """
    return [name for name in info.all_notes if name not in info.hidden_types]


def get_buf_quality_info(buf: Buffer) -> Struct:
    """Get the quality information stored for a buffer.

    The information structure is initialised if necessary.

    :buf: The buffer to query.
    """
    info = buf.store('quality_info')
    if info.hidden_types is None:
        info.hidden_types = set()
        info.all_notes = {}
        info.sign_to_note = {}
    return info


def trace(func):
    """Decorator to force traceback to be logged.

    This is useful for callback functions.

    :func: Function to be decorated.
    """
    def invoke(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:  # pylint: disable=broad-except
            vpe.log(e)
            traceback.print_exc(file=vpe.log)

    return invoke


class QualityNote:
    """A report from a code quality tool.

    :rep_dict: A dictionary containing details of the quality note.
               This should typically include a message, line and code.
               Optional standard items are col, type and name.

    @message: Free form message describing the quality observation.
    @line:    The line of the affected code.
    @col:     The column of the affected code (may be -1).
    @type:    A string indicating the type of observation, such as warning,
              note, refactor.
    @code:    A code identifying the type of observation.
    @name:    A name identifying the type of observation.
    """
    type_name: ClassVar[str]
    message: str = ''
    col: int = -1
    line: int = 0
    type: str = ''
    code: str = ''
    name: str = ''

    def __init__(self, rep_dict: Dict[str, Union[str, int]]):
        self.__dict__.update(rep_dict)

    def short_message(self):
        """Format a short form of a quality message."""
        return self.message.strip()

    def zap_comment(self) -> Optional[str]:
        """Format a comment to disable this quality report.

        Over-ridden by sub-classes. A return value of ``None`` indicates that
        there is no support for disabling using a code comment.
        """


class PyLintItem(QualityNote):
    """Details about a pylint note."""
    type_name = 'pylint'

    def zap_comment(self):
        """Format a comment to disable a pylint message."""
        return f'# pylint: disable={self.name}'


class PyCodeStyleItem(QualityNote):
    """Details about a pycodestyle note."""
    type_name = 'pycodestyle'

    def zap_comment(self):
        """Format a comment to disable a pycodestyle message."""
        return '# noqa'


class MyPyItem(QualityNote):
    """Details about a mypy message."""
    type_name = 'mypy'

    def zap_comment(self):
        """Format a comment to disable a mypy message."""
        if self.name:
            return f'# type: ignore[{self.name}]'
        return f'# type: ignore[{self.name!r}]'


def create_note(reporter: str, report: dict) -> Optional[QualityNote]:
    """Create the appropriate note for a given report.

    :reporter: The name of the quality reporter.
    :report:   The report generated by the reporte.
    """
    if reporter == 'pylint':
        return PyLintItem(report)
    if reporter == 'mypy':
        return MyPyItem(report)
    if reporter == 'pycodestyle':
        return PyCodeStyleItem(report)
    return None


class QualityPopup(vpe.Popup):
    """Popup window for quality observation reports.

    This handles the navigation keys.
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, channel, *args, **kwargs):
        super().__init__('<place-holder>', *args, **kwargs)
        self.channel = weakref.proxy(channel)

    def on_key(self, key: str, _byte_seq: bytes) -> bool:
        """Handle a key when menu is active."""
        if key == '<C-N>':
            self.channel.goto_next_report(offset=1)
        elif key == '<C-P>':
            self.channel.goto_next_report(offset=-1)
        else:
            return False
        return True


class QualityMenuPopup(vpe.Popup):
    """Popup window for quality co ntrol menu.

    This is used to select what quality information is displayed.
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, callback):
        super().__init__('', border=(1, 1, 1, 1), title='Select quality mode')
        self.callback = callback
        self.entries = []

    def on_close(self, _result: int) -> None:
        """Handle menu closure.

        :_result: Unused.
        """
        # Invoke callback with list of disabled types.
        self.callback([
            name for _, name, selected in self.entries if not selected])

    def set_choices(self, names, selected):
        """Set the choices for the menu.

        :names:    The list of names for the menu.
        :selected: A set of the names currently selected.
        """
        self.entries = []
        for i, name in enumerate(names):
            hot_key = f'{i + 1}'
            self.entries.append((hot_key, name, name in selected))
        self.update_text()

    def update_text(self):
        """Update the menu text according to the current entries."""
        lines = []
        for hot_key, name, selected in self.entries:
            mark = '[x]' if selected else '[ ]'
            lines.append(gen_rich_text(
                (f'{hot_key}', 'hot_key'),
                (f' {mark} ', ''),
                (f' {name}', ''),
            ))
        self.settext(lines)

    def on_key(self, key: str, _byte_seq: bytes) -> bool:
        """Handle a key when menu is active."""
        for i, (hot_key, name, selected) in enumerate(self.entries):
            if hot_key == key:
                selected = not selected
                self.entries[i] = hot_key, name, selected
                self.update_text()
                return True
        self.close()
        return False


class QualityServerChannel(channels.JsonChannel):
    """A channel managing use of the quality server."""
    # pylint: disable=too-many-instance-attributes

    info_popup: vpe.Popup
    autocmd_group = vpe.AutoCmdGroup('quality')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._menu = None
        self._signs = None
        self._reset()
        self.ping_resp = 1
        self.ping_req = 1
        self.show_info = True
        self.wd_timer = vpe.Timer(5000, self.on_watchdog_time, repeat=-1)
        self.conn_timer = vpe.Timer(500, self.try_connect, repeat=-1)
        self._create_resources()

    def _create_resources(self) -> None:
        """Create signs, highlight groups, *etc*."""
        self.resources_created = True
        self.info_popup = self._create_report_popup()
        sign_bg = vim.synIDattr(vim.synIDtrans(vim.hlID("SignColumn")), "bg")
        sign_hl = partial(vpe.highlight, guibg=sign_bg)
        sign_hl(group='VPE_qual_error', guifg='red')
        sign_hl(group='VPE_qual_fatal', guifg='yellow', guibg='yellow')
        sign_hl(group='VPE_qual_warning', guifg='SaddleBrown')
        sign_hl(group='VPE_qual_refactor', guifg='DarkOrchid')
        sign_hl(group='VPE_qual_convention', guifg='Wheat1')
        sign_hl(group='VPE_qual_other', guifg='blue')
        sg = Sign.get
        self._signs = {
            'E': sg('qual_error', text='E>', texthl='VPE_qual_error'),
            'error': sg('qual_error', text='E>', texthl='VPE_qual_error'),
            'F': sg('qual_fatal', text='F>', texthl='VPE_qual_fatal'),
            'W': sg('qual_warning', text='W>', texthl='VPE_qual_warning'),
            'note': sg('qual_warning', text='N>', texthl='VPE_qual_warning'),
            'R': sg('qual_refactor', text='R>', texthl='VPE_qual_refactor'),
            'C': sg(
                'qual_convention', text='C>', texthl='VPE_qual_convention'),
        }
        _props = vim.prop_type_list()
        for _name in _props:
            vim.prop_type_delete(_name)
        vim.prop_type_add('heading', {'highlight': 'Title'})
        vim.prop_type_add('message', {'highlight': 'Comment'})
        vim.prop_type_add('zapper', {'highlight': 'Identifier'})
        vim.prop_type_add('hot_key', {'highlight': 'VisualNOS'})
        vim.prop_type_add('type_name', {'highlight': 'ModeMsg'})

    def _reset(self) -> None:
        """Reset to well defined initial state."""
        mapping.nmap('<F12>', self.toggle_info, buffer=False)
        mapping.nmap('<C-F12>', self.activate_quality_menu, buffer=False)
        with self.autocmd_group as g:
            g.delete_all()
            g.add('CursorMoved', pat='*', func=self.on_cursor_moved)
            g.add('BufWritePost', pat='*', func=self.on_buf_write)
            g.add('BufReadPost', pat='*', func=self.on_buf_read)
            g.add('BufDelete', pat='*', func=self.on_buf_delete)

    def send(self, message: Message) -> None:
        """Send a message to the server."""
        if self.is_open:
            # vpe.log(f'Send: {message}')
            try:
                self.sendexpr(message.encode())
            except common.VimError:
                pass

    def on_connect(self):
        """Handler for a new outgoing connection."""
        for buf in vim.buffers:
            self.send(AddFileMessage(buf.name, buf.options.filetype))

    def on_buf_write(self) -> None:
        """Handle when changes have been written to the buffer."""
        bufnum = int(vim.expand('<abuf>'))
        buf = vim.buffers[bufnum]
        self.send(AddFileMessage(buf.name, buf.options.filetype))

    def on_buf_read(self) -> None:
        """Handle when a file has been read into a buffer."""
        bufnum = int(vim.expand('<abuf>'))
        buf = vim.buffers[bufnum]
        self.send(AddFileMessage(buf.name, buf.options.filetype))

    def on_buf_delete(self) -> None:
        """Handle when buffer is being deleted."""
        bufnum = int(vim.expand('<abuf>'))
        buf = vim.buffers[bufnum]
        self.send(RemoveFileMessage(buf.name, buf.options.filetype))

    def on_message(self, message: Any) -> None:
        """Handler called to process a new incoming message.

        :message: The incoming message.
        """
        try:
            _, code, details = message
        except ValueError:
            vpe.log("Invalid message", repr(message))
            return

        # vpe.log(f'Message: {code=}:')
        if code == 'ping':
            self.ping_resp = details['count']
            return
        if code != 'report':
            vpe.log(f'Cannot handle {code} messages!')
            return
        # for name, value in details.items():
        #     vpe.log(f'    {name}: {str(value)[:90]}')

        buf = vpe.find_buffer_by_name(details['path'])
        if buf is None:
            vpe.log(f'No buffer for file {details["path"]}!')
            return

        vpe.log(
            f'{len(details["reports"]):<3}: {details["reporter"]}'
            f' - {details["path"]}')
        self.store_quality_reports(
            buf, details['reporter'], details['reports'])
        self.place_report_signs(buf)

    @staticmethod
    def store_quality_reports(
            buf: vpe.wrappers.Buffer, reporter: str, reports: List[dict]):
        """Store quality reoprts for a buffer.

        :buf:      The buffer to update.
        :reporter: The name of the quality reporter.
        :reports:  The quality reports.
        """
        info = get_buf_quality_info(buf)
        notes = []
        for report in reports:
            notes.append(create_note(reporter, report))
        info.all_notes[reporter] = notes

    def place_report_signs(self, buf: Buffer) -> None:
        """Place signs in buffer for a list of reports.

        :buf: The target buffer.
        """
        if not buf.valid:
            return
        vim.sign_unplace('', {'buffer': buf.number})
        info = get_buf_quality_info(buf)
        all_notes = [info.all_notes[name] for name in enabled_types(info)]
        notes = itertools.chain(*all_notes)
        if not notes:
            return
        sign_to_note = {}
        for note in notes:
            options = {'lnum': int(note.line)}
            sign = self._signs.get(note.type)
            if sign is None:
                name = f'qual_{note.type}'
                sign = Sign.get(
                    name, f'{note.type}', texthl='VPE_qual_other')
            sid = vim.sign_place(0, '', sign.name, buf.number, options)
            sign_to_note[sid] = note
        info.sign_to_note = sign_to_note

    def try_connect(self, _timer) -> None:
        """"Try to establish a connection to a server.

        This is invoked by a timer. If a connection is already established then
        the timer is stopped. Otherwise a connection attempt is initiated.
        """
        if self.is_open and self.conn_timer:
            self.conn_timer.stop()
            self.conn_timer = None
        else:
            self.connect()

    def on_watchdog_time(self, _timer) -> None:
        """Timer used for watch dog activities."""
        if self.ping_req - self.ping_resp > 2:
            self.close()
            vpe.log(f'Server not responding {self.ping_req} {self.ping_resp}')
            vpe.log(f'Open flag={self.is_open}')
            self.ping_resp = self.ping_req
            if not self.conn_timer:
                self.conn_timer = vpe.Timer(500, self.try_connect, repeat=-1)
            self.connect()
        else:
            msg = PingMessage()
            self.send(msg)
            self.ping_req = msg.count

    @trace
    def activate_quality_menu(self, _info) -> None:
        """Bring up the quality menu."""
        def set_filter(hidden_types):
            info.hidden_types = set(hidden_types)
            self.place_report_signs(buf)

        buf = vim.current.buffer
        menu = self._menu = QualityMenuPopup(callback=set_filter)
        info = get_buf_quality_info(buf)

        menu.set_choices(info.all_notes, enabled_types(info))
        if len(menu.entries) > 0:
            menu.show()

    def toggle_info(self, _info) -> None:
        """Keymapping callback: toggle the quality popup."""
        if not vim.sign_getplaced('%') or self.info_popup.visible:
            self.info_popup.hide()
            self.show_info = False
            return

        self.show_info = True
        self.goto_next_report()

    def goto_next_report(self, offset: FindDirection = 0) -> None:
        """Goto the next pylint report."""
        if (lnum := self._find_next_report(offset)) is not None:
            vim.current.window.cursor = lnum, 0
            self.on_cursor_moved()

    def on_cursor_moved(self) -> None:
        """Handle when the cursor is moved."""
        if not self.show_info:
            self.info_popup.hide()
            return
        notes = self._get_reports_at_curline()
        if not notes:
            self.info_popup.hide()
            return

        self.info_popup.settext(self._format_report_text(notes))
        win = vim.current.window
        _, c = vim.win_screenpos(win.number)
        self.info_popup.line = 'cursor-1'
        self.info_popup.col = c + 2
        self.info_popup.show()

    @staticmethod
    def on_zap(_info, item) -> None:
        """Callback for a pylint zap mapping."""
        zap_comment = item.zap_comment()
        if not zap_comment:
            return
        buf = vim.current.buffer
        lnum, _ = vim.current.window.cursor
        text = f'{buf[lnum - 1]}  {zap_comment}'
        buf[lnum - 1] = text

    def _create_report_popup(self) -> vpe.Popup:
        """Create the information popup window.

        The window is initially hidden.
        """
        popup = QualityPopup(
            self, line='cursor-1', col='cursor', pos='botleft', mapping=True)
        popup.hide()
        return popup

    @staticmethod
    def _get_placed_signs(lnum: Optional[int] = None) -> List[dict]:
        """Get a list of placed signs for the current buffer.

        :lnum: If supplied, only query for the given line.
        :return:
            A list containing the sign placements. Each is a dict of group, id,
            lnum, name and priority - see :vim:`sign_getplaced` for details.
        """
        options = {} if lnum is None else {'lnum': lnum}
        placed = vim.sign_getplaced('%', options)
        if len(placed) == 0:
            return []
        return placed[0]['signs']

    def _find_next_report(
            self, offset: FindDirection = 0) -> Optional[int]:
        """Find the next line with a quality report sign.

        The offset controls how the search is performed. It should have only
        one of three values.

        -1:
            Search backward starting at the line before the current one.
        0:
            Search forward starting at the current line.
        1:
            Search forward starting at the line after the current one.

        :offset: The direction of search. Values other than -1, 0 or 1 will
                 produce unexpected results.
        :return:
            The line number of the next report or ``None`` if there is no next
            report.
        """
        def test(c, t):
            return c <= t if offset < 0 else c >= t

        if not (placements := self._get_placed_signs()):
            return None

        lnum = vim.current.window.cursor[0] + offset
        if offset < 0:
            placements = list(reversed(placements))
        for placement in placements:
            if test(sign_lnum := placement['lnum'], lnum):
                return sign_lnum

        return placements[-1]['lnum']

    def _get_reports_at_curline(self) -> List[QualityNote]:
        """Get all the quality reports for the current line."""
        lnum, _ = vim.current.window.cursor
        placements = self._get_placed_signs(lnum)
        info = get_buf_quality_info(vim.current.buffer)
        sign_to_note = info.sign_to_note
        pids = [p['id'] for p in placements]
        notes = [note for id in pids if (note := sign_to_note.get(id))]
        return notes

    def _format_report_text(self, items: List[QualityNote]) -> List[dict]:
        """Format the text of a pylint message."""
        lines = [
            gen_rich_text(
                ('Quality messages: ', 'heading'),
                ('<C-N> / <C-P>', 'zapper'),
                (' - next/previous report', 'heading'))]
        for i, item in enumerate(items, 1):
            msg = item.short_message()
            zap_keys = f'z{i}'
            lines.append(gen_rich_text(
                (f'{item.type_name}: ', 'type_name'),
                (f'{msg} (', 'message'),
                (zap_keys, 'zapper'),
                (')', 'message')))
            mapping.nmap(zap_keys, self.on_zap, args=(item,))
        return lines


class Sign:
    """A Vim sign.

    :name:   The name of the sign.
    :linehl: The highlight group foe a signed line.
    :text:   The sign text (up to 2 characters).
    :texthl: The highlight group for the sign text.
    """
    # pylint: disable=too-few-public-methods
    defined: Dict[str, Sign] = {}

    def __init__(
            self, name: str, text: str, *, linehl: str = None,
            texthl: str = None):
        self.defined[name] = self
        self.name = name
        options = core.build_dict_arg(
            ('linehl', linehl), ('text', text), ('texthl', texthl))
        vim.sign_define(name, options)

    @classmethod
    def get(
            cls, name: str, text: str, *, linehl: str = None,
            texthl: str = None) -> Sign:
        """Get a sign with a given name, creating is necessary.

        :name:   The name of the sign.
        :linehl: The highlight group foe a signed line.
        :text:   The sign text (up to 2 characters).
        :texthl: The highlight group for the sign text.
        :return:
            The `Sign` for he given name.
        """
        if name in cls.defined:
            return cls.defined[name]
        return cls(name, text, linehl=linehl, texthl=texthl)


def gen_rich_text(*parts: Tuple[str, str]) -> dict:
    """Generate rich text content.

    This is useful for setting the text in popup windows.

    :parts: Tuples of texts, prop_name. The prop_name may be an empty
            string.
    :return: A dict containing text and props entries.
    """
    s = []
    props = []
    col = 1
    for text, type_name in parts:
        s.append(text)
        if type_name:
            props.append({'col': col, 'length': len(text), 'type': type_name})
        col += len(text)
    return {'text': ''.join(s), 'props': props}


def create_channel():
    """Create the quality channel.

    This must not be invoked until v:did_enter is True.
    """
    global quality_channel  # pylint: disable=global-statement
    quality_channel = QualityServerChannel('localhost:8764')


def run():
    """Install the quality monitoring framework."""
    if vim.vvars.vim_did_enter:
        create_channel()
    else:
        with vpe.AutoCmdGroup('vpede') as g:
            g.add('VimEnter', create_channel, pat='*', once=True)


quality_channel: Optional[QualityServerChannel] = None


if __name__ == '__main__':
    vpe.commands.messages('clear')
    vpe.timer_stopall()
    vpe.popup_clear()
    vpe.log.set_maxlen(1000)
    vpe.log.clear()
    vpe.log.show()
    run()

    vim.command(
        'nnoremap <F4> :py3file'
        ' ~/.vim/pack/plugins/start/vpe_ide/plugin/vpede.py<cr>')
    vim.command('nnoremap <F3> :py3 quality_channel.send(QuitMessage())<cr>')
