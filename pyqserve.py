#!/usr/bin/env python
"""Python code quality server.

This is intended to be a general purpose server that will migrate to provide a
plug-in architecture for mini-services like python linting. Currently things
are rather hard-coded.
"""
from __future__ import annotations

from typing import Any, Iterator, Tuple, List, DefaultDict, Set, Counter
from typing import ClassVar, Optional, Dict, Collection, Callable
import asyncio
import collections
import json
import io
import itertools
import pathlib
import re
import time
import traceback
import weakref

ProtoMessage = Tuple[int, Tuple[int, str, Any]]
Path = pathlib.Path

# Protocol desciption.
#
# Messages to and from the server have the same basic form:
#
# [vuid, [uid, code, parameters]]
#
#     vuid:       int  The message ID as used by Vim's JSON channel.
#     uid:        int  Should be a unique (to the client) identifier.
#                      Only positive values a are allowed in client requests.
#                      The value zero is used for unsolicited messages from
#                      the server.
#     code:       str  Identifies the type of request, response or report.
#     parameters: dict A set of key-value pairs that vary according to the
#                      type of request/response.
#
# This format works cleanly with Vim's ch_evalexpr and ch_sendexpr methods.
# The message is JSON encoded, so Vim clients should  use a JSON configured
# channel.

r_pylint_msg = re.compile(r'''(?x)
    (?P<path> . *?) :             # File's path.
    (?P<line> \d+ ) :             # Line number.
    (?P<col> \d+ ) :              # Column number.
    [ ]                           # Single space
    (?P<type> [A-Z] )             # Type character
    (?P<code> \d+ ) :             # Code number
    [ ]                           # Single space
    (?P<message> . *?)            # The message string.
    \(
        (?P<name> [a-z][a-z-] *)  # The check's name.
    \)
''')

r_pycodestyle_msg = re.compile(r'''(?x)
    (?P<path> . *?) :             # File's path.
    (?P<line> \d+ ) :             # Line number.
    (?P<col> \d+ ) :              # Column number.
    [ ]                           # Single space
    (?P<type> [A-Z] )             # Type character
    (?P<code> \d+ )               # Code number
    [ ]                           # Single space
    (?P<message> . *)             # The message string.
''')

r_mypy_msg = re.compile(r'''(?x)
    (?P<path> . *?) :             # File's path.
    (?P<line> \d+ ) :             # Line number.
    [ ]                           # Single space
    (?P<type> [a-z]+ ) :          # Type name
    [ ]                           # Single space
    (?P<message> . *?)            # The message string.
    (?:
        [ ]+ \[                   # Spaces then
        (?P<name>                 #  [<error-name>] at end of line
          [a-z] [a-z-]*
        ) \]
    ) ?                           # is optionally present.
    $                             # Ensure whole line is consumed.
''')


class elapsed_timer:
    """Context manager to time a block of code.

    :name: The name to use when reporting the time taken.
    """
    start_time: float

    def __init__(self, name: str, enabled=True):
        self.name = name
        self.enabled = enabled

    def __enter__(self):
        self.start_time = time.time()

    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self.enabled:
            log(f'Ran {self.name} in {time.time() - self.start_time:.2f}s')


class Logger:
    """A simple logging facility."""
    # pylint: disable=too-few-public-methods
    def __init__(self):
        self.start_time = time.time()

    def __call__(self, *args):
        t = time.time()
        f = io.StringIO()
        print(*args, file=f)
        for i, line in enumerate(f.getvalue().splitlines()):
            if i == 0:
                prefix = f'{t - self.start_time:7.2f}:'
            else:
                prefix = '' * 9
            print(f'{prefix} {line}')


def find_file_here_or_above(
        here_path: Path, target_name: str) -> Optional[Path]:
    """Find a given file in or above another file's directory.

    The *here_path* indicates the first directory to look in. If *here_path*
    is a directory that is the start directory otherwise the here_path's
    directory is used. If not found successive parent directories are checked.

    :here_path:   The path of the file identifying wheare to start looking.
    :target_name: The name of the file to find.
    """
    start = here_path
    if here_path.is_dir():
        start = start / 'dummy'
    for dirname in start.resolve().parents:
        path = dirname / target_name
        if path.exists():
            return path
    return None


def make_full_path_name(work_dir: Path, path_name: str) -> str:
    """Optionally add work dir to a path name to form an absolute path.

    :work_dir:  The working directory to prepend if required.
    :path_name: The path name to convert to an absolute path.
    """
    path = Path(path_name)
    if not path.is_absolute():
        path = work_dir / path
    return str(path)


def fix_report_path_names(work_dir: Path, reports: List[dict]):
    """Fix all the paths in a quality report, making them absolute.

    :work_dir: The working directory where the reports wr generated.
    :reports:  The quality reports.
    """
    for report in reports:
        report['path'] = make_full_path_name(work_dir, report['path'])


def get_messages(
        decoder: json.JSONDecoder, buf: str) -> Iterator[Tuple[str, Any]]:
    """Parse individual messages from an input buffer.

    :decoder: A json decoder.
    :buf:     The buffer to decode.
    :yield:   Tuples of (unused-buf, message).
    """
    message = 'dummy'
    while buf and message:
        message = ''
        try:
            message, index = decoder.raw_decode(buf)
        except json.JSONDecodeError:
            log("Decode error", repr(buf))
            return
        except Exception:
            f = io.StringIO()
            traceback.print_exc(file=f)
            log(f.getvalue())
            raise

        buf = buf[index:].lstrip()
        yield buf, message


class RegularAction:
    """A regularly scheduled action.

    Uses asyncio's loop.call_later to make something happen at a regular
    interval.

    :period:   The timer's tick period in seconds.
    :function: The function to invoke for each tick.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, period: float, function: Callable[[], None]):
        self.function = function
        self.period = period
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(period, self._on_timer)

    def _on_timer(self):
        self.function()
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(self.period, self._on_timer)


class TaskTracker:
    """Mixin tthat tracks and cleans up asyncio tasks."""
    # pylint: disable=too-few-public-methods

    def __init__(self, *_args, **_kwargs):
        self.tasks: Set[asyncio.Task] = set()

    async def quit(self):
        """Stop all tasks then await them all."""
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


class Connection(TaskTracker):
    """A connection to a single client.

    :server: The server that accepted this connection.
    :number: A unique number for this connection.
    :reader: The StreamReader for this connection.
    :writer: The StreamWriter for this connection.

    @files: A set of the file paths added by this client.
    """
    file: Set[Path]

    def __init__(
            self, server: Server, number: int, reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter):
        super().__init__()
        self.server: Server = weakref.proxy(server)
        self.number: int = number
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.files = set()
        log(f'Incoming connection: {self.number}')
        self.tasks.add(asyncio.create_task(
            self.process_requests(), name=f'process {self.number}'))

    async def process_requests(self):
        """Process all incoming requests for this connection."""

        buf = ''
        decoder = json.JSONDecoder()
        while True:
            data = await self.reader.read(1024)
            if not data:
                log(f'Connection {self.number} closed')
                await self.quit()
                return
            buf += data.decode()
            for buf, message in get_messages(decoder, buf):
                self.tasks.add(asyncio.create_task(
                    self.process_message(message),
                    name=f'request {self.number}'))

    async def process_message(self, message: ProtoMessage):
        """Process a single message.

        :message: The message to process.
        """
        try:
            vuid, (uid, code, parameters) = message
        except (ValueError, TypeError):
            log("Bad message", repr(message))
            return
        if await self.server.process_message(code, message):
            return

        handler = getattr(self, f'handle_{code}', None)
        if handler is None:
            log(f'No handler for {code=} {code == "add_file"}')
            return

        await handler(vuid, uid, parameters)

    async def handle_add_file(
            self, _vuid: int, _uid: int, parameters: Dict[str, Any]):
        """Process the add_file message.

        :_vuid:      The message ID generated by Vim's JSON channel.
        :_uid:       The unique message ID.
        :parameters: A dictionary of parameters for the message.
        """
        path = Path(parameters['path'])
        if path not in self.files:
            log(f'Client[{self.number}]: Add file: {path}')
            self.files.add(path)
            self.server.add_file(path, parameters['type_name'])

    async def handle_remove_file(
            self, _vuid: int, _uid: int, parameters: Dict[str, Any]):
        """Process the remove_file message.

        :_vuid:      The message ID generated by Vim's JSON channel.
        :_uid:       The unique message ID.
        :parameters: A dictionary of parameters for the message.
        """
        path = Path(parameters['path'])
        if path in self.files:
            log(f'Client[{self.number}]: Remove file: {path}')
            self.files.remove(path)
            self.server.remove_file(path)

    async def handle_ping(
            self, vuid: int, _uid: int, parameters: Dict[str, Any]):
        """Process the ping message.

        :vuid:       The message ID generated by Vim's JSON channel.
        :_uid:       The unique message ID.
        :parameters: A dictionary of parameters for the message.
        """
        await self.send_response(vuid, PingResponse(parameters['count']))

    async def send_response(self, vuid: int, resp: ProtoMessage):
        """Send a response message.

        :vuid: The message ID as used by Vim's JSON channel.
        :resp: The response message to send.
        """
        msg = [vuid, resp.encode()]
        self.writer.write(json.dumps(msg).encode())
        await self.writer.drain()

    async def send_reports(
            self, type_name: str, reports_by_file: Dict[Path, List[str]]):
        """Send reports for a set of files.

        :type_name:      The name identifying the type of report, *e.g. pylint.
        reports_by_file: A dict of report messages, keyed by path.
        """
        for path, reports in reports_by_file.items():
            if path not in self.files:
                continue
            details = {
                'reporter': type_name, 'path': str(path), 'reports': reports}
            await self.send_report(Report(details))

    async def send_report(self, message: Message):
        """Send a report to a connection.

        This is used to send an unsolicited report to client.

        :message: The message to send.
        """
        full_msg = [0, message.encode()]
        msg = json.dumps(full_msg)
        self.writer.write(msg.encode())
        try:
            await self.writer.drain()
        except ConnectionError as e:
            log(f'Send failed for connection={self.number}, {e}')
            await self.quit()

    async def quit(self):
        """Stop processing requests from the client."""
        for path in self.files:
            log(f'Client[{self.number}]: Remove file: {path}')
            self.server.remove_file(path)
        await super().quit()
        self.server.process_connection_ended(self.number)


class Server(TaskTracker):
    """The interface to the quality server.

    @connections:
        Mapping from a unique number to a `Connection`.
    @all_files:
        Mapping from a path to the number of clients that hav registered the
        path. When the count reaches zero, the file is dropped.
    @server:
        The asyncio.Server instance.
    @analysers:
        A list of all the regietsred code analysers.
    @mod_times:
        A dictionary mapping from file path to is last noted modification time.
        This is used to trigger reports when a file is externally modified.
    """
    # pylint: disable=too-many-instance-attributes
    conn_counter: ClassVar[Iterator[int]] = itertools.count()

    all_files: Counter[Path]
    connections: Dict[int, Connection]
    server: Any
    analysers: List[Analyser]
    mod_times: DefaultDict[Path, float]
    _cleaup_action: RegularAction
    _check_action: RegularAction

    def __init__(self):
        super().__init__()
        self.connections = {}
        self.all_files = collections.Counter()
        self.am_quitting: bool = False
        self.analysers = []
        self.mod_times = collections.defaultdict(lambda: 0)

    async def on_connect(
            self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Callback for new incoming connection.

        :reader: The new StreamReader for the connection.
        :writer: The new StreamWriter for the connection.
        """
        number = next(self.conn_counter)
        self.connections[number] = Connection(self, number, reader, writer)

    def process_connection_ended(self, number: int):
        """Process notification that a connection has closed.

        This is invoked by one of the `connections`.

        :number: The connection's unique number.
        """
        self.connections.pop(number)

    async def process_message(self, code: str, _message: ProtoMessage) -> bool:
        """Process a single incoming message.

        This method assumes that the *message* is well formed.

        :code: The code already extraced from the *message*.
        :message: The message to process.
        :return:  True if the messages processed, false if it was ignored.
        """
        if code == 'quit':
            await self.quit()
            return True
        return False

    def add_file(self, path: Path, type_name: str):
        """Add a path to the set of all registered paths.

        :path:      The path to add.
        :type_name: The type name of the file; *e.g.* 'python'.
        """
        self.all_files[path] += 1
        log(f'Server: Add file: {path}: {self.all_files[path]}')
        if self.all_files[path] == 1:
            for analyser in self.analysers:
                analyser.add_file(path, type_name)

    def remove_file(self, path: Path):
        """Add a path to the set of all registered paths.

        :path:      The path to add.
        :type_name: The type name of the file; *e.g.* 'python'.
        """
        if path in self.all_files:
            self.all_files[path] -= 1
            if self.all_files[path] == 0:
                log(f'Server: Remove file: {path}')
                for analyser in self.analysers:
                    analyser.remove_file(path)

    async def update_reports(
            self, type_name: str, paths: Collection[Path],
            reports: List[dict]):
        """Update the quality reports for a set of files.

        :type_name: The name of the type of report; *e.g.* pylint.
        :paths:     A list of the file paths reported on.
        :reports:   A list of the reports.
        """
        all_paths = set(Path(report['path']) for report in reports)
        for path in paths:
            all_paths.add(path)
        reports_by_path = {path: [] for path in all_paths}
        for report in reports:
            reports_by_path[Path(report['path'])].append(report)
        for conn in list(self.connections.values()):
            await conn.send_reports(type_name, reports_by_path)

    def cleanup(self):
        """Perform cleanup of dead tasks, *etc*."""
        dead = [task for task in self.tasks if task.done()]
        for task in dead:
            # log(f'Removing task {task.get_name()}')
            self.tasks.remove(task)

    def check_times(self):
        """Perform modification time check for registered files."""
        modified = []
        for path in self.all_files:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if mtime > self.mod_times[path]:
                self.mod_times[path] = mtime
                modified.append(path)
        if modified:
            for analyser in self.analysers:
                analyser.note_modified(modified)

    def add_analyser(self, analyser: Analyser) -> None:
        """Add an anlyser.

        This will manage the life time of the analyser.

        :analyser: Any object providing the `Analyser` protocol.
        """
        self.analysers.append(analyser)
        analyser.set_parent(weakref.proxy(self))

    async def run(self):
        """Main execution for the server."""
        self._cleaup_action = RegularAction(2.0, self.cleanup)
        self._check_action = RegularAction(3.0, self.check_times)
        for analyser in self.analysers:
            self.tasks.add(asyncio.create_task(
                analyser.run(), name=analyser.name))
        self.server = await asyncio.start_server(
            self.on_connect, host='localhost', port=8764)
        log(f'Serving on {self.server.sockets[0].getsockname()}')
        try:
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            pass
        await self.server.wait_closed()
        await self.quit()

    async def quit(self):
        """Arrange to quit running."""
        if not self.am_quitting:
            log('Quitting!')
            self.am_quitting = True
            self.server.close()
            await super().quit()


class Analyser:
    """Base for all code analysers.

    This uses a pattern where analysed files are grouped together with a given
    configuration file (rcfile). A given rcfile is associated with all files
    in or below its containing directory.

    When a file in a group is found to have been updated then all the files in
    that group are scheduled to be (re)scanned. Only one scan for an rcfile is
    executing as any time. Each quality scan is executed in the rcfile's
    directory.
    """
    name: ClassVar[str] = ''
    file_types: ClassVar[Set[str]] = set()
    excl_suffixes: ClassVar[Set[str]] = set()
    rcname: ClassVar[str] = ''

    rc_sets: DefaultDict[Path, Set[Path]]
    op_queue: asyncio.Queue
    needs_scan: Set[Path]
    being_scanned: Dict[Path, asyncio.Task]
    parent: Optional[Server] = None

    def __init__(self):
        self.rc_sets = collections.defaultdict(set)
        self.files: Set[Path] = set()
        self.needs_scan = set()
        self.being_scanned = {}

    async def run(self):
        """Run quality analysis as required."""
        self.op_queue = asyncio.Queue()
        while True:
            op, arg = await self.op_queue.get()
            if op == 'scan':
                # log('Scan signalled')
                self.start_new_scans()
            elif op == 'complete':
                task = self.being_scanned.pop(arg)
                await task
                # log('Scan complete', arg)
                self.start_new_scans()

    def set_parent(self, parent: Server):
        """Set the parent server.

        :parent: The parent server.
        """
        self.parent = parent

    def add_file(self, path: Path, type_name: str) -> None:
        """Add a file to the list of those that should be quality checked.

        :path:      The file to be checked.
        :type_name: A string defining the type of file; *e.g.* python.
        """
        if type_name not in self.file_types:
            return
        if path.suffix in self.excl_suffixes:
            return
        rcpath = find_file_here_or_above(path, self.rcname)
        if rcpath is None:
            return
        log(f'Add {path} to {self.name} analysis set')
        self.rc_sets[rcpath].add(path)
        self.needs_scan.add(rcpath)
        self.start_new_scans()

    def remove_file(self, path: Path) -> None:
        """Remove a file from the list of those that should be quality checked.

        :path:      The file to be checked.
        """
        rcpath = find_file_here_or_above(path, self.rcname)
        if path in self.rc_sets[rcpath]:
            log(f'Remove {path} from {self.name} analysis set')
            self.rc_sets[rcpath].remove(path)

    def start_new_scans(self):
        """Start any new scans that are needed."""
        started = []
        for rcpath in self.needs_scan:
            if rcpath in self.being_scanned:
                continue
            self.being_scanned[rcpath] = asyncio.create_task(
                self.run_scan(rcpath), name=f'scan-{rcpath}')
            started.append(rcpath)
        for rcpath in started:
            self.needs_scan.remove(rcpath)

    def note_modified(self, modified: List[Path]) -> None:
        """Note that some files have been modified.

        :modified: A list of paths for the modified files.
        """
        for path in modified:
            for rcpath, rc_set in self.rc_sets.items():
                if path in rc_set:
                    self.needs_scan.add(rcpath)
        if self.needs_scan:
            self.op_queue.put_nowait(('scan', None))

    async def run_scan(self, rcpath: Path):
        """Run a single scan operation.

        :recpath: The path of the configuration file rcfile.
        """
        with elapsed_timer(f'{self.name} for {rcpath}'):
            work_dir = rcpath.parent
            paths = self.rc_sets[rcpath]
            file_names = [str(p) for p in paths]
            aproc = await self.exec_analyser(rcpath, file_names)
            reports = []
            while line := await aproc.stdout.readline():
                rep = self.parse_line(line.decode().rstrip())
                if rep:
                    reports.append(rep)
            await aproc.wait()

        self.op_queue.put_nowait(('complete', rcpath))
        fix_report_path_names(work_dir, reports)
        if self.parent is not None:
            await self.parent.update_reports(self.name, paths, reports)

    def exec_analyser(self, rcpath: Path, files: List[str]):
        """Create the quality analysis process.

        Concrete analyser's need to over-ride this.

        :rcpath: The configuration file.
        :files:  The files to be analysed.
        """

    @staticmethod
    def parse_line(line: str) -> dict:
        """Parse a line of analysis output.

        Concrete analyser's need to over-ride this.

        :line:   The line to parse.
        """


class PyAnalyser(Analyser):
    """Base for all Python code analysers."""

    file_types: ClassVar[Set[str]] = {'python'}
    excl_suffixes: ClassVar[Set[str]] = {'.pyi'}


class PyLinter(PyAnalyser):
    """Management of pylint quality checks."""

    name: ClassVar[str] = 'pylint'
    rcname: ClassVar[str] = 'pylintrc'

    def exec_analyser(self, rcpath: Path, files: List[str]):
        """Create the quality analysis process.

        :rcpath: The configuration file.
        :files:  The files to be analysed.
        """
        args = ['pylint', f'--rcfile={rcpath}', *files]
        return asyncio.create_subprocess_exec(
            *args, cwd=str(rcpath.parent), stdout=asyncio.subprocess.PIPE)

    @staticmethod
    def parse_line(line) -> dict:
        """Parse a line of analysis output.

        :line: The line to parse.
        """
        m = r_pylint_msg.match(line)
        if m:
            return m.groupdict()
        return {}


class PyCodeStyler(PyAnalyser):
    """Management of pycodestyle quality checks."""

    name: ClassVar[str] = 'pycodestyle'
    file_types: ClassVar[Set[str]] = {'python'}
    rcname: ClassVar[str] = 'setup.cfg'

    def exec_analyser(self, rcpath: Path, files: List[str]):
        """Create the quality analysis process.

        :rcpath: The configuration file.
        :files:  The files to be analysed.
        """
        return asyncio.create_subprocess_exec(
            'pycodestyle', *files, cwd=str(rcpath.parent),
            stdout=asyncio.subprocess.PIPE)

    @staticmethod
    def parse_line(line) -> dict:
        """Parse a line of analysis output.

        :line: The line to parse.
        """
        m = r_pycodestyle_msg.match(line)
        if m:
            return m.groupdict()
        return {}


class MyPyer(PyAnalyser):
    """Management of mypy static analysis."""

    name: ClassVar[str] = 'mypy'
    rcname: ClassVar[str] = 'mypy.ini'

    def exec_analyser(self, rcpath: Path, files: List[str]):
        """Create the quality analysis process.

        :rcpath: The configuration file.
        :files:  The files to be analysed.
        """
        return asyncio.create_subprocess_exec(
            'mypy', f'--config-file={rcpath}', cwd=str(rcpath.parent),
            stdout=asyncio.subprocess.PIPE)

    @staticmethod
    def parse_line(line) -> dict:
        """Parse a line of analysis output.

        :line: The line to parse.
        """
        m = r_mypy_msg.match(line)
        if m:
            return m.groupdict()
        return {}


class Message:
    """Generic message."""
    # pylint: disable=too-few-public-methods
    req_counter: Iterator[int] = itertools.count(1)
    code: str = ''

    def __init__(
            self, parameters: Optional[dict] = None,
            request: Optional[int] = None):
        if request is None:
            self.req_number = next(self.req_counter)
        else:
            self.req_number = request
        self.parameters = parameters or {}

    def encode(self):
        """Encode into a form suitable for a JSON channel."""
        return [self.req_number, self.code, self.parameters]


class Report(Message):
    """An unsolicited report."""
    # pylint: disable=too-few-public-methods
    code: str = 'report'

    def __init__(self, parameters: Optional[dict] = None):
        super().__init__(parameters, request=0)


class PingResponse(Message):
    """Keep-alive ping."""
    # pylint: disable=too-few-public-methods

    code: str = 'ping'
    ping_count: ClassVar[Iterator[int]] = itertools.count()

    def __init__(self, count: int = -1):
        self.count = count if count >= 0 else next(self.ping_count)
        super().__init__({'count': self.count})


if __name__ == "__main__":
    log = Logger()
    _server = Server()
    _server.add_analyser(PyLinter())
    _server.add_analyser(PyCodeStyler())
    _server.add_analyser(MyPyer())
    asyncio.run(_server.run())
