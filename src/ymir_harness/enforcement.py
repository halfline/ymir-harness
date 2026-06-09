from __future__ import annotations

import asyncio
import io
import json
import os
import shlex
import socket
import subprocess
from contextvars import ContextVar
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request

from ymir_harness.replay import ReplayCache, ReplayCacheError, ReplayResponse, request_url
from ymir_harness.safety import (
    detect_replay_violations,
    detect_unsafe_command,
    detect_unsafe_http_request,
)


class BenchmarkBoundaryViolation(RuntimeError):
    """Raised when a benchmark run attempts forbidden I/O."""


_MODEL_SOCKET_PASSTHROUGH = ContextVar("ymir_harness_model_socket_passthrough", default=False)
MODEL_PROVIDER_HOSTS = {
    "anthropic": ("api.anthropic.com",),
    "gemini": ("generativelanguage.googleapis.com",),
    "openai": ("api.openai.com",),
    "vertexai": (
        "aiplatform.googleapis.com",
        "oauth2.googleapis.com",
    ),
}


@dataclass(frozen=True)
class _SubprocessReplay:
    returncode: int
    stdout_body: bytes
    stderr_body: bytes


@contextmanager
def enforce_benchmark_boundaries(environment: Mapping[str, str]) -> Iterator[None]:
    network_mode = environment.get("YMIR_BENCHMARK_NETWORK_MODE")
    replay_cache = _replay_cache(environment)
    recorded_urls = _recorded_urls(environment, replay_cache)
    mock_git_urls = _mock_git_urls(environment)
    model_hosts = _model_provider_hosts(environment)
    active_network_guard = network_mode in {"replay_only", "network_denied"}

    originals = _PatchState.capture()
    try:
        _patch_subprocess(originals, network_mode, replay_cache, recorded_urls, mock_git_urls)
        _patch_asyncio_subprocess(
            originals,
            network_mode,
            replay_cache,
            recorded_urls,
            mock_git_urls,
        )
        if active_network_guard:
            _patch_socket(originals)
            _patch_urllib(originals, network_mode, replay_cache, model_hosts)
            _patch_requests(originals, network_mode, replay_cache, model_hosts)
            _patch_aiohttp(originals, network_mode, replay_cache, model_hosts)
        yield
    finally:
        originals.restore()


class _PatchState:
    def __init__(self) -> None:
        self.socket_connect = socket.socket.connect
        self.socket_connect_ex = socket.socket.connect_ex
        self.subprocess_run = subprocess.run
        self.subprocess_popen = subprocess.Popen
        self.asyncio_create_subprocess_exec = asyncio.create_subprocess_exec
        self.asyncio_create_subprocess_shell = asyncio.create_subprocess_shell
        self.urllib_urlopen = None
        self.requests_request = None
        self.aiohttp_request = None
        self.requests_session = None
        self.aiohttp_client_session = None

    @classmethod
    def capture(cls) -> "_PatchState":
        state = cls()
        import urllib.request

        state.urllib_urlopen = urllib.request.urlopen

        try:
            import requests.sessions  # type: ignore[import-not-found]
        except ImportError:
            pass
        else:
            state.requests_session = requests.sessions.Session
            state.requests_request = requests.sessions.Session.request

        try:
            import aiohttp  # type: ignore[import-not-found]
        except ImportError:
            pass
        else:
            state.aiohttp_client_session = aiohttp.ClientSession
            state.aiohttp_request = aiohttp.ClientSession._request

        return state

    def restore(self) -> None:
        socket.socket.connect = self.socket_connect
        socket.socket.connect_ex = self.socket_connect_ex
        subprocess.run = self.subprocess_run
        subprocess.Popen = self.subprocess_popen
        asyncio.create_subprocess_exec = self.asyncio_create_subprocess_exec
        asyncio.create_subprocess_shell = self.asyncio_create_subprocess_shell

        import urllib.request

        if self.urllib_urlopen is not None:
            urllib.request.urlopen = self.urllib_urlopen

        if self.requests_session is not None and self.requests_request is not None:
            self.requests_session.request = self.requests_request

        if self.aiohttp_client_session is not None and self.aiohttp_request is not None:
            self.aiohttp_client_session._request = self.aiohttp_request


def _patch_subprocess(
    originals: _PatchState,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    recorded_urls: Sequence[str],
    mock_git_urls: Sequence[str],
) -> None:
    def guarded_run(command: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        _check_command(
            command,
            network_mode=network_mode,
            replay_cache=replay_cache,
            recorded_urls=recorded_urls,
            mock_git_urls=mock_git_urls,
        )
        replayed = _replayed_shell_download(command, replay_cache, kwargs)
        if replayed is not None:
            return replayed
        replay_miss = _replay_miss_subprocess(
            command,
            network_mode=network_mode,
            mock_git_urls=mock_git_urls,
            kwargs=kwargs,
        )
        if replay_miss is not None:
            return replay_miss
        return originals.subprocess_run(command, *args, **kwargs)

    class guarded_popen(subprocess.Popen):  # type: ignore[type-arg]
        def __init__(self, command: Any, *args: Any, **kwargs: Any) -> None:
            self._is_replay_process = False
            _check_command(
                command,
                network_mode=network_mode,
                replay_cache=replay_cache,
                recorded_urls=recorded_urls,
                mock_git_urls=mock_git_urls,
            )
            replay = _subprocess_replay(command, replay_cache, network_mode, mock_git_urls)
            if replay is not None:
                self._is_replay_process = True
                self._init_replay(command, replay, kwargs)
                return
            super().__init__(command, *args, **kwargs)

        def _init_replay(
            self,
            command: Any,
            replay: _SubprocessReplay,
            kwargs: Mapping[str, Any],
        ) -> None:
            stdout_target = kwargs.get("stdout")
            stderr_target = kwargs.get("stderr")
            stdout = _stream_value(stdout_target, replay.stdout_body, kwargs)
            stderr = _stream_value(stderr_target, replay.stderr_body, kwargs)
            if stderr_target == subprocess.STDOUT and stdout is not None:
                addition = _output_value(replay.stderr_body, kwargs)
                stdout = stdout + addition if addition is not None else stdout
                stderr = None

            self.args = command
            self.pid = 0
            self.returncode = replay.returncode
            self.stdin = (
                _pipe_reader(b"", kwargs) if kwargs.get("stdin") == subprocess.PIPE else None
            )
            self.stdout = _pipe_reader(stdout, kwargs) if stdout_target == subprocess.PIPE else None
            self.stderr = _pipe_reader(stderr, kwargs) if stderr_target == subprocess.PIPE else None
            self._replay_stdout = stdout
            self._replay_stderr = stderr
            self._child_created = False

        def communicate(self, input: Any = None, timeout: float | None = None) -> tuple[Any, Any]:
            if not self._is_replay_process:
                return super().communicate(input=input, timeout=timeout)
            return self._replay_stdout, self._replay_stderr

        def wait(self, timeout: float | None = None) -> int:
            if not self._is_replay_process:
                return super().wait(timeout=timeout)
            return int(self.returncode)

        def poll(self) -> int:
            if not self._is_replay_process:
                return super().poll()
            return int(self.returncode)

        def kill(self) -> None:
            if not self._is_replay_process:
                super().kill()
                return
            self.returncode = -9

        def terminate(self) -> None:
            if not self._is_replay_process:
                super().terminate()
                return
            self.returncode = -15

        def __enter__(self) -> "guarded_popen":
            if not self._is_replay_process:
                return super().__enter__()
            return self

        def __exit__(self, *_exc_info: object) -> None:
            if not self._is_replay_process:
                super().__exit__(*_exc_info)
                return
            self.wait()

        def __del__(self) -> None:
            if not self._is_replay_process:
                super().__del__()

    subprocess.run = guarded_run
    subprocess.Popen = guarded_popen


def _patch_asyncio_subprocess(
    originals: _PatchState,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    recorded_urls: Sequence[str],
    mock_git_urls: Sequence[str],
) -> None:
    async def guarded_create_subprocess_exec(
        program: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        command = [program, *args]
        _check_command(
            command,
            network_mode=network_mode,
            replay_cache=replay_cache,
            recorded_urls=recorded_urls,
            mock_git_urls=mock_git_urls,
        )
        replay = _subprocess_replay(command, replay_cache, network_mode, mock_git_urls)
        if replay is not None:
            return _AsyncReplayProcess(command, replay, kwargs)
        return await originals.asyncio_create_subprocess_exec(program, *args, **kwargs)

    async def guarded_create_subprocess_shell(
        cmd: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        _check_command(
            cmd,
            network_mode=network_mode,
            replay_cache=replay_cache,
            recorded_urls=recorded_urls,
            mock_git_urls=mock_git_urls,
        )
        replay = _subprocess_replay(cmd, replay_cache, network_mode, mock_git_urls)
        if replay is not None:
            return _AsyncReplayProcess(cmd, replay, kwargs)
        return await originals.asyncio_create_subprocess_shell(cmd, *args, **kwargs)

    asyncio.create_subprocess_exec = guarded_create_subprocess_exec
    asyncio.create_subprocess_shell = guarded_create_subprocess_shell


class _AsyncReplayProcess:
    def __init__(
        self,
        command: Any,
        replay: _SubprocessReplay,
        kwargs: Mapping[str, Any],
    ) -> None:
        stdout_target = kwargs.get("stdout")
        stderr_target = kwargs.get("stderr")
        stdout_body = replay.stdout_body
        stderr_body = replay.stderr_body
        if stderr_target == subprocess.STDOUT:
            stdout_body += stderr_body
            stderr_body = b""

        self.args = command
        self.pid = 0
        self.returncode = replay.returncode
        self.stdin = None
        self.stdout = _AsyncPipeReader(stdout_body) if stdout_target == subprocess.PIPE else None
        self.stderr = _AsyncPipeReader(stderr_body) if stderr_target == subprocess.PIPE else None
        self._stdout_body = stdout_body if stdout_target == subprocess.PIPE else None
        self._stderr_body = stderr_body if stderr_target == subprocess.PIPE else None
        _write_async_redirect(stdout_target, stdout_body)
        if stderr_target != subprocess.STDOUT:
            _write_async_redirect(stderr_target, stderr_body)

    async def communicate(self, input: bytes | None = None) -> tuple[bytes | None, bytes | None]:
        del input
        return self._stdout_body, self._stderr_body

    async def wait(self) -> int:
        return int(self.returncode)

    def send_signal(self, signal: int) -> None:
        self.returncode = -int(signal)

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9


class _AsyncPipeReader:
    def __init__(self, body: bytes) -> None:
        self._stream = io.BytesIO(body)

    async def read(self, n: int = -1) -> bytes:
        return self._stream.read(n)

    async def readline(self) -> bytes:
        return self._stream.readline()

    async def readexactly(self, n: int) -> bytes:
        value = self._stream.read(n)
        if len(value) != n:
            raise asyncio.IncompleteReadError(value, n)
        return value

    def at_eof(self) -> bool:
        current = self._stream.tell()
        self._stream.seek(0, io.SEEK_END)
        end = self._stream.tell()
        self._stream.seek(current)
        return current >= end


def _write_async_redirect(target: Any, body: bytes) -> None:
    if target in {None, subprocess.PIPE, subprocess.DEVNULL, subprocess.STDOUT}:
        return
    if hasattr(target, "write"):
        target.write(body)


def _check_command(
    command: Any,
    *,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    recorded_urls: Sequence[str],
    mock_git_urls: Sequence[str],
) -> None:
    tokens = _command_tokens(command)
    command_tokens = _tokens_after_env(tokens)
    operations = detect_unsafe_command(command_tokens or tokens, source="subprocess")
    if operations:
        operation = operations[0]
        raise BenchmarkBoundaryViolation(f"unsafe operation blocked: {operation.detail}")

    if network_mode in {"replay_only", "network_denied"}:
        external_urls = _external_urls(tokens)
        replayable_download = (
            network_mode == "replay_only"
            and _is_shell_download(command)
            and external_urls
            and all(_can_replay_url(url, replay_cache, recorded_urls) for url in external_urls)
        )
        mock_git_command = _is_mock_git_command(tokens, external_urls, mock_git_urls)
        if (
            network_mode == "network_denied"
            and external_urls
            and not (replayable_download or mock_git_command)
        ):
            raise BenchmarkBoundaryViolation(f"external subprocess URL blocked: {external_urls[0]}")
        if network_mode == "replay_only" and external_urls:
            return
        if replayable_download:
            return
        if mock_git_command:
            return
        violations = detect_replay_violations(
            [{"argv": tokens}],
            recorded_urls=recorded_urls,
        )
        if violations:
            raise BenchmarkBoundaryViolation(f"fixture replay violation blocked: {violations[0]}")


def _replayed_shell_download(
    command: Any,
    replay_cache: ReplayCache | None,
    kwargs: Mapping[str, Any],
) -> subprocess.CompletedProcess[Any] | None:
    replay = _cached_shell_download(command, replay_cache)
    if replay is None:
        return None
    return _completed_process(
        command,
        replay.returncode,
        stdout_body=replay.stdout_body,
        stderr_body=replay.stderr_body,
        kwargs=kwargs,
    )


def _subprocess_replay(
    command: Any,
    replay_cache: ReplayCache | None,
    network_mode: str | None,
    mock_git_urls: Sequence[str],
) -> _SubprocessReplay | None:
    cached = _cached_shell_download(command, replay_cache)
    if cached is not None:
        return cached
    return _replay_miss_subprocess_payload(
        command,
        network_mode=network_mode,
        mock_git_urls=mock_git_urls,
    )


def _cached_shell_download(
    command: Any,
    replay_cache: ReplayCache | None,
) -> _SubprocessReplay | None:
    if replay_cache is None or not _is_shell_download(command):
        return None

    urls = _external_urls(_command_tokens(command))
    if len(urls) != 1 or not replay_cache.has_url(urls[0]):
        return None

    return _SubprocessReplay(
        returncode=0,
        stdout_body=replay_cache.read_bytes(urls[0]),
        stderr_body=b"",
    )


def _replay_miss_subprocess(
    command: Any,
    *,
    network_mode: str | None,
    mock_git_urls: Sequence[str],
    kwargs: Mapping[str, Any],
) -> subprocess.CompletedProcess[Any] | None:
    replay = _replay_miss_subprocess_payload(
        command,
        network_mode=network_mode,
        mock_git_urls=mock_git_urls,
    )
    if replay is None:
        return None
    return _completed_process(
        command,
        replay.returncode,
        stdout_body=replay.stdout_body,
        stderr_body=replay.stderr_body,
        kwargs=kwargs,
    )


def _replay_miss_subprocess_payload(
    command: Any,
    *,
    network_mode: str | None,
    mock_git_urls: Sequence[str],
) -> _SubprocessReplay | None:
    if network_mode != "replay_only":
        return None

    tokens = _command_tokens(command)
    external_urls = _external_urls(tokens)
    if not external_urls or _is_mock_git_command(tokens, external_urls, mock_git_urls):
        return None

    body = b"".join(_replay_miss_body(url) for url in external_urls)
    if _is_shell_download(command):
        return _SubprocessReplay(returncode=0, stdout_body=body, stderr_body=b"")

    stderr = b"".join(_replay_miss_body(url) for url in external_urls)
    returncode = 128 if _is_git_command(tokens) else 1
    return _SubprocessReplay(returncode=returncode, stdout_body=b"", stderr_body=stderr)


def _completed_process(
    command: Any,
    returncode: int,
    *,
    stdout_body: bytes,
    stderr_body: bytes,
    kwargs: Mapping[str, Any],
) -> subprocess.CompletedProcess[Any]:
    stdout_target = subprocess.PIPE if kwargs.get("capture_output") else kwargs.get("stdout")
    stderr_target = subprocess.PIPE if kwargs.get("capture_output") else kwargs.get("stderr")
    stdout = _stream_value(stdout_target, stdout_body, kwargs)
    stderr = _stream_value(stderr_target, stderr_body, kwargs)
    if stderr_target == subprocess.STDOUT and stdout is not None:
        addition = _output_value(stderr_body, kwargs)
        stdout = stdout + addition if addition is not None else stdout
        stderr = None
    completed = subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)
    if kwargs.get("check"):
        completed.check_returncode()
    return completed


def _stream_value(target: Any, body: bytes, kwargs: Mapping[str, Any]) -> Any:
    if target is None or target == subprocess.DEVNULL:
        return None
    value = _output_value(body, kwargs)
    if target == subprocess.PIPE:
        return value
    if hasattr(target, "write") and value is not None:
        try:
            target.write(value)
        except TypeError:
            target.write(body)
    return None


def _pipe_reader(value: Any, kwargs: Mapping[str, Any]) -> Any:
    if value is None:
        value = _output_value(b"", kwargs)
    if isinstance(value, str):
        return io.StringIO(value)
    return io.BytesIO(value)


def _output_value(body: bytes, kwargs: Mapping[str, Any]) -> Any:
    if kwargs.get("text") or kwargs.get("encoding") or kwargs.get("universal_newlines"):
        return body.decode(
            kwargs.get("encoding") or "utf-8",
            errors=kwargs.get("errors") or "strict",
        )
    return body


def _can_replay_url(
    url: str,
    replay_cache: ReplayCache | None,
    recorded_urls: Sequence[str],
) -> bool:
    if url in recorded_urls:
        return True
    return replay_cache is not None and replay_cache.has_url(url)


def _patch_socket(originals: _PatchState) -> None:
    def guarded_connect(sock: socket.socket, address: Any) -> Any:
        _check_socket_address(address)
        return originals.socket_connect(sock, address)

    def guarded_connect_ex(sock: socket.socket, address: Any) -> int:
        _check_socket_address(address)
        return originals.socket_connect_ex(sock, address)

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex


def _check_socket_address(address: Any) -> None:
    if _MODEL_SOCKET_PASSTHROUGH.get():
        return
    if not isinstance(address, tuple) or not address:
        return
    host = str(address[0])
    if host in {"127.0.0.1", "::1", "localhost"}:
        return
    raise BenchmarkBoundaryViolation(f"external network connection blocked: {host}")


def _patch_urllib(
    originals: _PatchState,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    model_hosts: Sequence[str],
) -> None:
    import urllib.request

    def guarded_urlopen(url: str | Request, *args: Any, **kwargs: Any) -> Any:
        request = url
        target_url = (
            request.full_url if isinstance(request, Request) else request_url(url, args, kwargs)
        )
        if target_url is None:
            return originals.urllib_urlopen(url, *args, **kwargs)
        method = request.get_method() if isinstance(request, Request) else "GET"
        _check_http_operation(method, target_url, source="urllib")
        if (
            network_mode == "replay_only"
            and replay_cache is not None
            and replay_cache.has_url(target_url)
        ):
            return replay_cache.open_urllib_response(target_url)
        if _is_model_provider_url(target_url, model_hosts):
            with _model_socket_passthrough():
                return originals.urllib_urlopen(url, *args, **kwargs)
        if network_mode == "replay_only":
            raise _replay_miss_http_error(target_url)
        _raise_network_violation(network_mode, target_url)
        return originals.urllib_urlopen(url, *args, **kwargs)

    urllib.request.urlopen = guarded_urlopen


def _patch_requests(
    originals: _PatchState,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    model_hosts: Sequence[str],
) -> None:
    if originals.requests_session is None or originals.requests_request is None:
        return

    def guarded_request(session: Any, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
        _check_http_operation(method, url, source="requests")
        if network_mode == "replay_only" and replay_cache is not None and replay_cache.has_url(url):
            import requests  # type: ignore[import-not-found]

            body = replay_cache.read_bytes(url)
            response = requests.Response()
            response.status_code = replay_cache.status_code(url)
            response.url = url
            response._content = body
            response.headers.update(replay_cache.response_headers(url, body))
            response.request = requests.Request(method=method, url=url).prepare()
            return response
        if _is_model_provider_url(url, model_hosts):
            with _model_socket_passthrough():
                return originals.requests_request(session, method, url, *args, **kwargs)
        if network_mode == "replay_only":
            return _replay_miss_requests_response(method, url)
        _raise_network_violation(network_mode, url)
        return originals.requests_request(session, method, url, *args, **kwargs)

    originals.requests_session.request = guarded_request


def _patch_aiohttp(
    originals: _PatchState,
    network_mode: str | None,
    replay_cache: ReplayCache | None,
    model_hosts: Sequence[str],
) -> None:
    if originals.aiohttp_client_session is None or originals.aiohttp_request is None:
        return

    async def guarded_request(
        session: Any, method: str, url: str, *args: Any, **kwargs: Any
    ) -> Any:
        target_url = str(url)
        _check_http_operation(method, target_url, source="aiohttp")
        if (
            network_mode == "replay_only"
            and replay_cache is not None
            and replay_cache.has_url(target_url)
        ):
            return replay_cache.open_aiohttp_response(target_url)
        if _is_model_provider_url(target_url, model_hosts):
            with _model_socket_passthrough():
                return await originals.aiohttp_request(session, method, url, *args, **kwargs)
        if network_mode == "replay_only":
            return ReplayResponse(
                target_url,
                _replay_miss_body(target_url),
                headers=_replay_miss_headers(),
                status=404,
            )
        _raise_network_violation(network_mode, target_url)
        return await originals.aiohttp_request(session, method, url, *args, **kwargs)

    originals.aiohttp_client_session._request = guarded_request


@contextmanager
def _model_socket_passthrough() -> Iterator[None]:
    token = _MODEL_SOCKET_PASSTHROUGH.set(True)
    try:
        yield
    finally:
        _MODEL_SOCKET_PASSTHROUGH.reset(token)


def _model_provider_hosts(environment: Mapping[str, str]) -> tuple[str, ...]:
    model_name = environment.get("CHAT_MODEL", "")
    prefix = model_name.split(":", 1)[0].lower()
    return MODEL_PROVIDER_HOSTS.get(prefix, ())


def _is_model_provider_url(url: str | None, allowed_hosts: Sequence[str]) -> bool:
    if not url or not allowed_hosts:
        return False
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        return False
    host = parsed.hostname.lower()
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)


def _check_http_operation(method: str, url: str, *, source: str) -> None:
    operation = detect_unsafe_http_request(method, url, source=source)
    if operation:
        raise BenchmarkBoundaryViolation(f"unsafe operation blocked: {operation.detail}")


def _replay_miss_requests_response(method: str, url: str) -> Any:
    import requests  # type: ignore[import-not-found]

    body = _replay_miss_body(url)
    response = requests.Response()
    response.status_code = 404
    response.reason = "Replay miss"
    response.url = url
    response._content = body
    response.headers.update(_replay_miss_headers())
    response.request = requests.Request(method=method, url=url).prepare()
    return response


def _replay_miss_http_error(url: str) -> HTTPError:
    body = _replay_miss_body(url)
    return HTTPError(url, 404, "Replay miss", _replay_miss_headers(), io.BytesIO(body))


def _replay_miss_body(url: str) -> bytes:
    return f"replay miss: URL is not recorded in replay cache: {url}\n".encode("utf-8")


def _replay_miss_headers() -> dict[str, str]:
    return {"Content-Type": "text/plain; charset=utf-8"}


def _raise_network_violation(network_mode: str | None, url: str) -> None:
    if network_mode == "network_denied":
        raise BenchmarkBoundaryViolation(f"external network access blocked: {url}")


def _replay_cache(environment: Mapping[str, str]) -> ReplayCache | None:
    try:
        return ReplayCache.from_environment(environment)
    except ReplayCacheError as exc:
        raise BenchmarkBoundaryViolation(str(exc)) from exc


def _recorded_urls(
    environment: Mapping[str, str],
    replay_cache: ReplayCache | None,
) -> tuple[str, ...]:
    encoded = environment.get("YMIR_BENCHMARK_RECORDED_URLS")
    urls = []
    if encoded:
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError:
            value = []
        if isinstance(value, list):
            urls.extend(url for url in value if isinstance(url, str) and url)
    if replay_cache is not None:
        urls.extend(replay_cache.recorded_urls)
    return tuple(dict.fromkeys(urls))


def _mock_git_urls(environment: Mapping[str, str]) -> tuple[str, ...]:
    encoded = environment.get("MOCK_BLOCKED_URLS", "")
    urls = []
    for line in encoded.splitlines():
        url = line.strip()
        if not url:
            continue
        urls.extend(_git_url_aliases(url))
    return tuple(dict.fromkeys(urls))


def _command_tokens(command: Any) -> list[str]:
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    if isinstance(command, Sequence):
        return [str(part) for part in command]
    return [str(command)]


def _is_shell_download(command: Any) -> bool:
    tokens = _command_tokens(command)
    if not tokens:
        return False
    command_tokens = _tokens_after_env(tokens)
    return bool(command_tokens) and PathName(command_tokens[0]).name in {"curl", "wget"}


def _is_mock_git_command(
    tokens: Sequence[str],
    external_urls: Sequence[str],
    mock_git_urls: Sequence[str],
) -> bool:
    if not external_urls or not mock_git_urls:
        return False
    command_tokens = _tokens_after_env(tokens)
    if not command_tokens or PathName(command_tokens[0]).name != "git":
        return False
    mock_url_set = set(mock_git_urls)
    return all(url in mock_url_set for url in external_urls)


def _is_git_command(tokens: Sequence[str]) -> bool:
    command_tokens = _tokens_after_env(tokens)
    return bool(command_tokens) and PathName(command_tokens[0]).name == "git"


def _tokens_after_env(tokens: Sequence[str]) -> list[str]:
    output = list(tokens)
    if output and PathName(output[0]).name == "env":
        output = output[1:]
        while output and output[0].startswith("-"):
            option = output.pop(0)
            if option in {"-i", "--ignore-environment", "-0", "--null"}:
                continue
            if option in {"-u", "--unset"} and output:
                output.pop(0)
                continue
            if option.startswith(("-u=", "--unset=")):
                continue
            break
    while output and _is_env_assignment(output[0]):
        output.pop(0)
    return output


def _is_env_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    if not separator or not name:
        return False
    return all(char == "_" or char.isalnum() for char in name)


def _external_urls(tokens: Sequence[str]) -> list[str]:
    urls = []
    for token in tokens[1:]:
        parsed = urlparse(token)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            urls.append(token)
    return urls


def _git_url_aliases(url: str) -> tuple[str, ...]:
    aliases = [url]
    if url.endswith(".git"):
        aliases.append(url.removesuffix(".git"))
    else:
        aliases.append(f"{url}.git")
    return tuple(dict.fromkeys(aliases))


class PathName(str):
    @property
    def name(self) -> str:
        return os.path.basename(self)
