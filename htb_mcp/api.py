from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_API_BASE = "https://labs.hackthebox.com/api/"
DEFAULT_USER_AGENT = "htb-mcp/0.1.0"
ZIP_PASSWORD = b"hackthebox"
SHERLOCK_ZIP_PASSWORD = b"hacktheblue"
PAGE_SIZE = 100
MAX_PAGES = 50


class HtbApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class HtbApiConfig:
    token: str
    api_base_url: str = DEFAULT_API_BASE
    user_agent: str = DEFAULT_USER_AGENT
    verify_ssl: bool = True


class _StripAuthOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None

        source = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(newurl)
        if source.netloc != target.netloc:
            redirected.remove_header("Authorization")
        return redirected


def _url(config: HtbApiConfig, endpoint: str, api_version: str = "v4") -> str:
    base = config.api_base_url.rstrip("/") + "/"
    return urllib.parse.urljoin(base, f"{api_version}/{endpoint.lstrip('/')}")


def _headers(config: HtbApiConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {config.token}",
        "User-Agent": config.user_agent,
        "Accept": "application/json",
    }


def _ssl_context(config: HtbApiConfig) -> ssl.SSLContext | None:
    if config.verify_ssl:
        return None
    return ssl._create_unverified_context()


def _decode_error(error: urllib.error.HTTPError) -> str:
    body = error.read()
    if not body:
        return str(error)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body.decode("utf-8", errors="replace")
    if isinstance(data, dict):
        return str(data.get("message") or data)
    return str(data)


def _http_error_message(
    error: urllib.error.HTTPError, method: str, url: str
) -> str:
    detail = _decode_error(error)
    return f"{method} {url} failed with HTTP {error.code}: {detail}"


def request_json(
    config: HtbApiConfig,
    method: str,
    endpoint: str,
    payload: dict[str, Any] | None = None,
    *,
    api_version: str = "v4",
) -> dict[str, Any]:
    body = None
    headers = _headers(config)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        _url(config, endpoint, api_version=api_version),
        data=body,
        headers=headers,
        method=method,
    )

    while True:
        try:
            with urllib.request.urlopen(
                request, context=_ssl_context(config), timeout=30
            ) as response:
                data = response.read()
            return json.loads(data.decode("utf-8")) if data else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                time.sleep(1)
                continue
            raise HtbApiError(
                _http_error_message(exc, method, request.full_url)
            ) from exc
        except urllib.error.URLError as exc:
            raise HtbApiError(f"{method} {request.full_url} failed: {exc.reason}") from exc


def request_bytes(
    config: HtbApiConfig, endpoint: str, *, api_version: str = "v4"
) -> bytes:
    url = (
        endpoint
        if endpoint.startswith(("http://", "https://"))
        else _url(config, endpoint, api_version=api_version)
    )
    request = urllib.request.Request(
        url,
        headers=_headers(config),
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context(config)),
        _StripAuthOnCrossHostRedirect(),
    )
    while True:
        try:
            with opener.open(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                time.sleep(1)
                continue
            raise HtbApiError(
                _http_error_message(exc, "GET", request.full_url)
            ) from exc
        except urllib.error.URLError as exc:
            raise HtbApiError(f"GET {request.full_url} failed: {exc.reason}") from exc


def _safe_extract_zip(
    archive: zipfile.ZipFile, destination: Path, password: bytes | None = None
) -> None:
    destination = destination.resolve()
    for member in archive.infolist():
        member_path = Path(member.filename)
        if member_path.is_absolute():
            raise HtbApiError(
                f"Refusing to extract absolute archive path: {member.filename}"
            )
        target_path = (destination / member.filename).resolve()
        try:
            target_path.relative_to(destination)
        except ValueError as exc:
            raise HtbApiError(
                f"Refusing to extract archive path outside destination: {member.filename}"
            ) from exc
    archive.extractall(destination, pwd=password)


def _extract_list_payload(data: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("info", "data", "machines", "challenges"):
        items = data.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    raise HtbApiError(
        f"HTB API response did not contain a list payload: keys={sorted(data.keys())}"
    )


def _with_query(endpoint: str, **params: Any) -> str:
    query = {
        key: value
        for key, value in params.items()
        if value is not None and value != ""
    }
    if not query:
        return endpoint
    pairs: list[tuple[str, Any]] = []
    for key, value in query.items():
        if isinstance(value, (list, tuple)):
            pairs.extend((f"{key}[]", item) for item in value)
        else:
            pairs.append((key, value))
    return f"{endpoint}?{urllib.parse.urlencode(pairs)}"


def _as_list(value: str | list[str] | None) -> list[str] | None:
    if value is None:
        return None
    items = value if isinstance(value, list) else str(value).split(",")
    cleaned = [str(item).strip() for item in items if str(item).strip()]
    return cleaned or None


def paginate(
    config: HtbApiConfig,
    endpoint: str,
    *,
    api_version: str = "v4",
    limit: int | None = None,
    **params: Any,
) -> tuple[list[dict[str, Any]], int | None]:
    """Fetch every page of a Laravel-style paginated endpoint.

    Returns (items, total). Stops early once `limit` items are collected.
    """
    items: list[dict[str, Any]] = []
    total: int | None = None
    page = 1
    while page <= MAX_PAGES:
        data = request_json(
            config,
            "GET",
            _with_query(endpoint, per_page=PAGE_SIZE, page=page, **params),
            api_version=api_version,
        )
        items.extend(_extract_list_payload(data))
        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        total = meta.get("total", total)
        last_page = int(meta.get("last_page") or page)
        if (limit and len(items) >= limit) or page >= last_page:
            break
        page += 1
    if limit:
        items = items[:limit]
    return items, total


def _resolve_category_ids(
    config: HtbApiConfig, endpoint: str, categories: list[str] | None
) -> list[str] | None:
    if not categories:
        return None
    data = request_json(config, "GET", endpoint, api_version="v4")
    known = {
        str(item.get("name", "")).casefold(): str(item.get("id"))
        for item in data.get("info") or []
        if isinstance(item, dict)
    }
    resolved = []
    for category in categories:
        if category.isdigit():
            resolved.append(category)
        elif category.casefold() in known:
            resolved.append(known[category.casefold()])
        else:
            raise HtbApiError(
                f'Unknown category "{category}". Known: {", ".join(sorted(known))}'
            )
    return resolved


def list_machines(
    config: HtbApiConfig,
    *,
    state: str | None = None,
    status: str | None = None,
    difficulty: str | list[str] | None = None,
    os: str | list[str] | None = None,
    keyword: str | None = None,
    free: bool | None = None,
    limit: int | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """List machines via the v5 endpoint, following pagination.

    state: active | retired. status: completed | incompleted (filtered
    client-side on root owns, the API ignores it for machines).
    """
    status_filter = (status or "").strip().lower() or None
    if status_filter not in (None, "completed", "incompleted"):
        raise HtbApiError('status must be "completed" or "incompleted".')
    items, total = paginate(
        config,
        "machines",
        api_version="v5",
        limit=None if status_filter else limit,
        state=state,
        keyword=keyword.strip() if keyword else None,
        difficulty=[d.lower() for d in _as_list(difficulty) or []] or None,
        os=[o.lower() for o in _as_list(os) or []] or None,
        free=None if free is None else int(free),
    )
    if status_filter:
        wanted = status_filter == "completed"
        items = [m for m in items if bool(m.get("authUserInRootOwns")) == wanted]
        total = len(items)
        if limit:
            items = items[:limit]
    return items, total


def get_machine(config: HtbApiConfig, machine_id_or_name: int | str) -> dict[str, Any]:
    value = urllib.parse.quote(str(machine_id_or_name).strip(), safe="")
    try:
        data = request_json(config, "GET", f"machine/profile/{value}")
    except HtbApiError as exc:
        raise HtbApiError(f'No machine "{machine_id_or_name}" was found: {exc}') from exc
    info = data.get("info")
    if not isinstance(info, dict):
        raise HtbApiError(f'No machine "{machine_id_or_name}" was found.')
    return info


def get_active_machine(config: HtbApiConfig) -> dict[str, Any] | None:
    data = request_json(config, "GET", "machine/active", api_version="v4")
    info = data.get("info")
    return info if isinstance(info, dict) else None


def start_machine(config: HtbApiConfig, machine_id: int) -> dict[str, Any]:
    request_json(
        config, "POST", "vm/spawn", {"machine_id": machine_id}, api_version="v4"
    )
    for _ in range(120):
        machine = get_active_machine(config)
        if (
            machine
            and int(machine.get("id", -1)) == machine_id
            and machine.get("ip")
            and not machine.get("isSpawning")
            and not (machine.get("playInfo") or {}).get("isSpawning")
        ):
            return machine
        time.sleep(1)
    raise HtbApiError("Timed out waiting for the machine to start.")


def submit_machine_flag(
    config: HtbApiConfig, flag: str, machine_id: int | None = None
) -> dict[str, Any]:
    target_id = machine_id
    if target_id is None:
        active = get_active_machine(config)
        if not active or active.get("id") is None:
            raise HtbApiError(
                "No active machine found. Start a machine first or provide its id."
            )
        target_id = int(active["id"])
    return request_json(
        config, "POST", "machine/own", {"id": target_id, "flag": flag}, api_version="v5"
    )


def list_challenges(
    config: HtbApiConfig,
    *,
    state: str | None = None,
    status: str | None = None,
    difficulty: str | list[str] | None = None,
    category: str | list[str] | None = None,
    keyword: str | None = None,
    limit: int | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """List challenges via /v4/challenges, following pagination.

    state: active | retired | unreleased. status: complete | incompleted.
    difficulty: very easy, easy, medium, hard, insane. category: names or ids.
    """
    status_value = (status or "").strip().lower() or None
    if status_value == "completed":
        status_value = "complete"
    return paginate(
        config,
        "challenges",
        limit=limit,
        state=state,
        status=status_value,
        keyword=keyword.strip() if keyword else None,
        difficulty=[d.lower() for d in _as_list(difficulty) or []] or None,
        category=_resolve_category_ids(
            config, "challenge/categories/list", _as_list(category)
        ),
    )


def get_challenge(
    config: HtbApiConfig, challenge_id_or_name: int | str
) -> dict[str, Any]:
    value = urllib.parse.quote(str(challenge_id_or_name), safe="")
    data = request_json(config, "GET", f"challenge/info/{value}", api_version="v4")
    challenge = data.get("challenge")
    if not isinstance(challenge, dict):
        raise HtbApiError("HTB API response did not contain a challenge object.")
    return challenge


def challenge_instance_address(
    challenge: dict[str, Any],
) -> tuple[str | None, list[Any]]:
    play_info = challenge.get("play_info") if isinstance(challenge.get("play_info"), dict) else {}
    host = challenge.get("docker_ip") or play_info.get("ip")
    ports = challenge.get("docker_ports") or play_info.get("ports") or []
    if not isinstance(ports, list):
        ports = [ports]
    return host, ports


def start_challenge_instance(config: HtbApiConfig, challenge_id: int) -> dict[str, Any]:
    request_json(
        config,
        "POST",
        "container/start",
        {"containerable_id": challenge_id},
        api_version="v4",
    )
    for _ in range(120):
        challenge = get_challenge(config, challenge_id)
        if challenge_instance_address(challenge)[0]:
            return challenge
        time.sleep(1)
    raise HtbApiError("Timed out waiting for the challenge instance to start.")


def download_challenge_zip(
    config: HtbApiConfig,
    challenge: dict[str, Any],
    destination: Path,
    *,
    unzip: bool = True,
    clear: bool = True,
) -> Path:
    challenge_id = int(challenge["id"])
    name = str(challenge.get("name") or challenge_id).strip().replace(" ", "_")
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = destination / f"{name}.zip"

    data = request_bytes(config, f"challenge/download/{challenge_id}", api_version="v4")
    zip_path.write_bytes(data)

    expected_sha = str(challenge.get("sha256") or "").strip()
    if expected_sha:
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            raise HtbApiError(
                f"Download hash mismatch: expected {expected_sha}, got {actual_sha}."
            )

    if unzip:
        with zipfile.ZipFile(zip_path) as archive:
            password = challenge.get("file_password")
            _safe_extract_zip(
                archive,
                destination,
                password=str(password).encode() if password else ZIP_PASSWORD,
            )
        if clear:
            zip_path.unlink()

    return zip_path


def prepare_challenge(
    config: HtbApiConfig,
    challenge_id_or_name: int | str,
    destination: Path,
    *,
    start_instance: bool = True,
) -> dict[str, Any]:
    challenge = get_challenge(config, challenge_id_or_name)
    has_download = bool(challenge.get("download"))
    play_methods = challenge.get("play_methods") or []
    has_docker = bool(challenge.get("docker")) or "docker" in play_methods

    result: dict[str, Any] = {
        "challenge": challenge,
        "downloaded_to": None,
        "instance": None,
    }

    if has_download:
        download_challenge_zip(config, challenge, destination, unzip=True, clear=True)
        result["downloaded_to"] = str(destination.resolve())

    if start_instance and has_docker:
        started = start_challenge_instance(config, int(challenge["id"]))
        host, ports = challenge_instance_address(started)
        result["instance"] = {
            "host": host,
            "ports": ports,
            "target": f"{host}:{ports[0]}" if host and ports else host,
        }

    if not has_download and not (start_instance and has_docker):
        raise HtbApiError(
            f'Challenge "{challenge.get("name", challenge_id_or_name)}" has no downloadable files or startable instance.'
        )

    return result


def submit_challenge_flag(
    config: HtbApiConfig, challenge_id: int, flag: str, difficulty: int = 1
) -> dict[str, Any]:
    return request_json(
        config,
        "POST",
        "challenge/own",
        {"flag": flag, "challenge_id": challenge_id, "difficulty": difficulty * 10},
        api_version="v4",
    )


def list_sherlocks(
    config: HtbApiConfig,
    *,
    state: str | None = None,
    status: str | None = None,
    difficulty: str | list[str] | None = None,
    category: str | list[str] | None = None,
    keyword: str | None = None,
    limit: int | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """List sherlocks via /v4/sherlocks, following pagination."""
    status_value = (status or "").strip().lower() or None
    if status_value == "completed":
        status_value = "complete"
    return paginate(
        config,
        "sherlocks",
        limit=limit,
        state=state,
        status=status_value,
        keyword=keyword.strip() if keyword else None,
        difficulty=[d.lower() for d in _as_list(difficulty) or []] or None,
        category=_resolve_category_ids(
            config, "sherlocks/categories/list", _as_list(category)
        ),
    )


def get_sherlock(config: HtbApiConfig, sherlock_id_or_name: int | str) -> dict[str, Any]:
    value = str(sherlock_id_or_name).strip()
    if not value:
        raise HtbApiError("Sherlock name cannot be empty.")

    if not value.isdigit():
        matches, _ = list_sherlocks(config, keyword=value)
        exact = [
            s for s in matches if str(s.get("name", "")).strip().casefold() == value.casefold()
        ]
        if not exact:
            raise HtbApiError(f'No sherlock named "{value}" was found.')
        value = str(exact[0]["id"])

    data = request_json(config, "GET", f"sherlocks/{value}", api_version="v4")
    sherlock = data.get("data")
    if not isinstance(sherlock, dict):
        raise HtbApiError(f'No sherlock "{sherlock_id_or_name}" was found.')
    return sherlock


def download_sherlock_zip(
    config: HtbApiConfig,
    sherlock_id_or_name: int | str,
    destination: Path,
    *,
    unzip: bool = True,
    clear: bool = True,
) -> dict[str, Any]:
    sherlock = get_sherlock(config, sherlock_id_or_name)
    sherlock_id = int(sherlock["id"])
    link = request_json(config, "GET", f"sherlocks/{sherlock_id}/download_link")
    url = link.get("url")
    if not url:
        raise HtbApiError("HTB API did not return a sherlock download link.")

    name = str(sherlock.get("name") or sherlock_id).strip().replace(" ", "_")
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = destination / f"{name}.zip"
    zip_path.write_bytes(request_bytes(config, url))

    password = str(sherlock.get("file_password") or SHERLOCK_ZIP_PASSWORD.decode())
    extracted = False
    if unzip:
        extracted = _extract_encrypted_zip(zip_path, destination, password)
        if extracted and clear:
            zip_path.unlink()

    return {
        "sherlock": sherlock,
        "downloaded_to": str(destination.resolve()),
        "extracted": extracted,
        "zip_path": None if extracted and clear else str(zip_path.resolve()),
        "zip_password": password,
    }


def _extract_encrypted_zip(zip_path: Path, destination: Path, password: str) -> bool:
    """Extract a zip that may use AES encryption (unsupported by zipfile).

    Tries the stdlib first, then 7z. Returns False if no method worked.
    """
    with zipfile.ZipFile(zip_path) as archive:
        try:
            _safe_extract_zip(archive, destination, password=password.encode())
            return True
        except NotImplementedError:
            pass  # AES: validate paths already done by _safe_extract_zip's loop
    for tool in ("7z", "7za", "7zz"):
        binary = shutil.which(tool)
        if not binary:
            continue
        result = subprocess.run(
            [binary, "x", "-y", f"-p{password}", f"-o{destination}", str(zip_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
    return False


def get_sherlock_play(config: HtbApiConfig, sherlock_id_or_name: int | str) -> dict[str, Any]:
    sherlock = get_sherlock(config, sherlock_id_or_name)
    data = request_json(config, "GET", f"sherlocks/{int(sherlock['id'])}/play", api_version="v4")
    play = data.get("data")
    if not isinstance(play, dict):
        raise HtbApiError("HTB API response did not contain a sherlock play payload.")
    return play


def list_sherlock_tasks(
    config: HtbApiConfig, sherlock_id_or_name: int | str
) -> list[dict[str, Any]]:
    sherlock = get_sherlock(config, sherlock_id_or_name)
    data = request_json(config, "GET", f"sherlocks/{int(sherlock['id'])}/tasks", api_version="v4")
    return _extract_list_payload(data)


def submit_sherlock_task_flag(
    config: HtbApiConfig,
    sherlock_id_or_name: int | str,
    task_id: int,
    flag: str,
) -> dict[str, Any]:
    sherlock = get_sherlock(config, sherlock_id_or_name)
    return request_json(
        config,
        "POST",
        f"sherlocks/{int(sherlock['id'])}/tasks/{task_id}/flag",
        {"flag": flag},
        api_version="v4",
    )
