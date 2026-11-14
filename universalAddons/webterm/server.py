"""Web terminal websocket service (runs as root under cp-webterm.service).

Flow for one connection:
1. The browser connects to the websocket path (through OpenLiteSpeed, or directly with TLS).
2. Its first message must be {"ticket": ..., "cols": .., "rows": ..} within AUTH_TIMEOUT seconds.
   The ticket was issued by the panel after it checked the session, site ownership and policy;
   it is consumed exactly once and must come from the same client address and panel origin.
3. shell.build_spawn() decides the Linux account (the site's own user; root only when policy
   and an admin ticket allow it) and the shell starts on a pty with that identity.
4. Frames: client -> server text "0<data>" is keyboard input, "1{"cols":..,"rows":..}" a resize;
   server -> client binary frames carry terminal output.
Sessions end on disconnect, shell exit, IDLE_TIMEOUT without input or MAX_SESSION seconds.
Start/stop are written to the audit log; keystrokes and output never are.
"""
import asyncio
import json
import os
import signal
import ssl
import sys
import time

sys.path.insert(0, '/usr/local/CyberCP')

from universalAddons.webterm import service, shell, tickets  # noqa: E402

AUTH_TIMEOUT = 10
IDLE_TIMEOUT = 15 * 60
MAX_SESSION = 2 * 60 * 60
MAX_PENDING = 20            # connections that have not authenticated yet
READ_CHUNK = 65536
MAX_FRAME = 64 * 1024

LIMITS = shell.SessionLimits(per_user=3, total=10)
_pending = 0


def _header(connection, name):
    try:
        return connection.request.headers.get(name, '') or ''
    except AttributeError:
        return ''


async def _first_message(connection):
    raw = await asyncio.wait_for(connection.recv(), AUTH_TIMEOUT)
    if not isinstance(raw, str) or len(raw) > 4096:
        raise tickets.TicketError('Invalid hello.')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise tickets.TicketError('Invalid hello.')
    return data


async def _pump_output(connection, fd, state):
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue(maxsize=64)

    def readable():
        try:
            chunk = os.read(fd, READ_CHUNK)
        except OSError:
            chunk = b''
        if not chunk:
            loop.remove_reader(fd)
        try:
            queue.put_nowait(chunk)
        except asyncio.QueueFull:
            # The browser is not keeping up: pause reading until the queue drains.
            loop.remove_reader(fd)
            state['paused'] = chunk

    loop.add_reader(fd, readable)
    state['resume'] = lambda: loop.add_reader(fd, readable)
    try:
        while True:
            chunk = await queue.get()
            if not chunk:
                return 'shell exited'
            await connection.send(chunk)
            if state.get('paused') is not None and queue.empty():
                pending, state['paused'] = state['paused'], None
                if pending:
                    await connection.send(pending)
                state['resume']()
    finally:
        try:
            loop.remove_reader(fd)
        except (ValueError, OSError):
            pass


async def _pump_input(connection, fd, state):
    while True:
        message = await connection.recv()
        state['last_input'] = time.monotonic()
        if not isinstance(message, str) or not message:
            continue
        kind, payload = message[0], message[1:]
        if kind == '0':
            data = payload.encode('utf-8', 'surrogateescape')
            while data:
                written = os.write(fd, data)
                data = data[written:]
        elif kind == '1':
            try:
                size = json.loads(payload)
                fitted = shell.clamp_size(size.get('cols'), size.get('rows'))
            except (ValueError, AttributeError):
                fitted = None
            if fitted:
                shell.set_size(fd, *fitted)


async def _watchdog(state, started):
    while True:
        await asyncio.sleep(15)
        now = time.monotonic()
        if now - state['last_input'] > IDLE_TIMEOUT:
            return 'idle timeout'
        if now - started > MAX_SESSION:
            return 'session time limit'


async def handle(connection):
    global _pending
    config = service.load_config()
    peer = connection.remote_address[0] if connection.remote_address else ''
    address = service.client_address(peer, _header(connection, 'X-Forwarded-For'), config['trust_proxy'],
                                     _header(connection, 'CF-Connecting-IP'))
    origin = _header(connection, 'Origin')
    if _pending >= MAX_PENDING:
        await connection.close(1013, 'busy')
        return
    _pending += 1
    try:
        try:
            hello = await _first_message(connection)
            record = tickets.consume(str(hello.get('ticket', '')), address)
            if not service.origin_allowed(origin, record.get('host'), config['public_url']):
                raise tickets.TicketError('Origin not allowed.')
            spec = shell.build_spawn(record, service.terminal_policy())
            key = str(record.get('user_id'))
            LIMITS.acquire(key)
        except (tickets.TicketError, shell.ShellError, ValueError, asyncio.TimeoutError) as exc:
            service.audit('refused', ip=address or peer, reason=str(exc))
            await connection.close(4001, str(exc)[:100])
            return
    finally:
        _pending -= 1

    size = shell.clamp_size(hello.get('cols'), hello.get('rows')) or (80, 24)
    pid, fd = shell.spawn(spec, *size)
    os.set_blocking(fd, False)
    started = time.monotonic()
    address = address or 'proxied'
    service.audit('start', panel_user=record.get('username'), unix_user=spec.user, site=record.get('domain'),
                  ip=address, pid=pid)
    state = {'last_input': started, 'paused': None}
    tasks = [asyncio.ensure_future(_pump_output(connection, fd, state)),
             asyncio.ensure_future(_pump_input(connection, fd, state)),
             asyncio.ensure_future(_watchdog(state, started))]
    reason = 'disconnected'
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if not task.cancelled() and task.exception() is None and isinstance(task.result(), str):
                reason = task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.get_running_loop().run_in_executor(None, shell.terminate, pid, fd)
        LIMITS.release(key)
        service.audit('stop', panel_user=record.get('username'), unix_user=spec.user, site=record.get('domain'),
                      ip=address, seconds=int(time.monotonic() - started), reason=reason)
        try:
            await connection.close(1000, reason[:100])
        except Exception:
            pass


def process_request(connection, request):
    if request.path.split('?', 1)[0] != service.WS_PATH:
        return connection.respond(404, 'Not found\n')
    return None


def _tls_context(config):
    if not config['tls']:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['cert'], config['key'])
    return context


async def main():
    from websockets.asyncio.server import serve
    config = service.load_config()
    stop = asyncio.get_running_loop().create_future()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set_result, None)
    async with serve(handle, config['listen'], config['port'], ssl=_tls_context(config),
                     process_request=process_request, max_size=MAX_FRAME, max_queue=32,
                     ping_interval=30, ping_timeout=30, compression=None):
        service.audit('service-start', listen=config['listen'], port=config['port'])
        await stop
    service.audit('service-stop')


if __name__ == '__main__':
    os.umask(0o077)
    asyncio.run(main())
