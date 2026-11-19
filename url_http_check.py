"""Asynchronous, resumable HTTP checks stored in the existing SQLite database."""

from __future__ import annotations

import argparse
import asyncio
import email.utils
import hashlib
import json
import random
import re
import socket
import sqlite3
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx
import idna


DATABASE = Path("database/url_analysis.db")
URL_TABLES = (
    "url_ok",
    "url_podezrele_vycistene",
    "url_odmitnute_vycistene",
)
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
HEAD_GET_FALLBACK = {403, 404, 405, 410, 429}
CLASSIFICATION_VERSION = "2026-09-09-v3"
SELECTION_VERSION = "2026-09-10-v4"
ENGINE_VERSION = "2026-09-09-v4"
UNCERTAIN_CLASSIFICATIONS = {
    "forbidden",
    "rate_limited",
    "server_error",
    "timeout",
    "dns_error",
    "tls_error",
    "connection_error",
}


@dataclass(frozen=True)
class Settings:
    concurrency: int = 10
    per_domain: int = 2
    retries: int = 3
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    write_timeout: float = 10.0
    pool_timeout: float = 10.0
    max_redirects: int = 10
    backoff_base: float = 1.0
    backoff_max: float = 15.0
    request_strategy: str = "get"
    max_body_bytes: int = 65536
    user_agent: str = (
        "MFFURLCheckBot/1.0 "
        "(https://webarchiv.cz/; webarchiv@webarchiv.cz) "
        "httpx/0.28.1"
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify(
    status_code: int | None,
    error_type: str | None,
    redirect_count: int = 0,
) -> str:
    if error_type:
        return error_type
    if status_code is None:
        return "connection_error"
    if status_code == 202:
        return "accepted_pending"
    if status_code == 204:
        return "no_content"
    if 200 <= status_code < 300:
        return "redirected_working" if redirect_count else "working"
    if status_code in {404, 410}:
        return "probably_missing"
    if status_code == 403:
        return "forbidden"
    if status_code == 429:
        return "rate_limited"
    if status_code == 401:
        return "authentication_required"
    if status_code == 451:
        return "legal_restriction"
    if 500 <= status_code < 600:
        return "server_error"
    if 300 <= status_code < 400:
        return "redirect_error"
    if 400 <= status_code < 500:
        return "client_error"
    return "http_error"


def validate_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        return str(exc)
    if parsed.scheme.lower() not in {"http", "https"}:
        return "URL nemá schéma http nebo https."
    if not parsed.hostname:
        return "URL nemá hostitele."
    if any(character.isspace() for character in url):
        return "URL obsahuje bílé znaky."
    return None


def url_features(url: str) -> dict[str, Any]:
    quality = "clean"
    reason = None
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
    except ValueError as exc:
        return {
            "input_quality_class": "invalid_syntax",
            "input_issue_reason": str(exc),
            "url_host": None,
            "url_tld": None,
            "url_scope": None,
            "path_depth": None,
        }
    if url.endswith((">", "]", "}")):
        quality = "suspected_trailing_artifact"
        reason = f"Podezřelý koncový znak {url[-1]!r}."
    elif url.endswith(")"):
        quality = "needs_manual_review"
        reason = "Koncová závorka může být součást URL nebo citační artefakt."
    elif host in {"localhost", "example.com", "example.org", "example.net"}:
        quality = "placeholder"
        reason = "Lokální nebo ukázkový hostname."
    elif host.endswith((".local", ".localhost")):
        quality = "private_or_local"
        reason = "Lokální hostname."
    depth = len([part for part in path.split("/") if part])
    tld = host.rsplit(".", 1)[-1] if "." in host else None
    return {
        "input_quality_class": quality,
        "input_issue_reason": reason,
        "url_host": host or None,
        "url_tld": tld,
        "url_scope": "root" if depth == 0 else "deep",
        "path_depth": depth,
    }


def redirect_type(original_url: str, final_url: str | None, count: int) -> str:
    if not count or not final_url:
        return "none"
    try:
        original = urlsplit(original_url)
        final = urlsplit(final_url)
    except ValueError:
        return "other"
    original_host = (original.hostname or "").lower()
    final_host = (final.hostname or "").lower()
    normalized_original = original_host.removeprefix("www.")
    normalized_final = final_host.removeprefix("www.")
    original_path = original.path or "/"
    final_path = final.path or "/"
    if (
        normalized_original == normalized_final
        and original_path == final_path
        and original.scheme == "http"
        and final.scheme == "https"
    ):
        return "http_to_https"
    if normalized_original == normalized_final and original_host != final_host:
        return "www_change"
    if original_path not in {"", "/"} and final_path in {"", "/"}:
        return "to_root"
    if original_host == final_host:
        return "same_host_path"
    if original_host != final_host:
        return "host_change"
    return "other"


def body_diagnostics(body: bytes, content_type: str | None) -> tuple[str | None, str | None]:
    if not body:
        return None, None
    fingerprint = hashlib.sha256(body).hexdigest()
    if not content_type or "html" not in content_type.lower():
        return None, fingerprint
    text = body.decode("utf-8", errors="replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = None
    if match:
        title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()
        title = title[:500] or None
    normalized = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()
    if normalized:
        fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return title, fingerprint


def error_kind(exc: BaseException) -> str:
    if isinstance(exc, (httpx.InvalidURL, httpx.UnsupportedProtocol)):
        return "invalid_url"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    text = " ".join(str(item) for item in chain).lower()
    if any(isinstance(item, socket.gaierror) for item in chain) or any(
        marker in text
        for marker in ("getaddrinfo", "name or service not known", "nodename nor servname")
    ):
        return "dns_error"
    if any(isinstance(item, ssl.SSLError) for item in chain) or any(
        marker in text
        for marker in ("certificate_verify_failed", "certificate verify failed", "ssl:", "tls")
    ):
        return "tls_error"
    if isinstance(exc, httpx.TooManyRedirects):
        return "redirect_error"
    return "connection_error"


def retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


def backoff(settings: Settings, attempt: int, retry_after: str | None) -> float:
    server_delay = retry_after_seconds(retry_after)
    if server_delay is not None:
        return min(server_delay, settings.backoff_max)
    return min(settings.backoff_base * (2**attempt), settings.backoff_max)


async def request_once(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    settings: Settings,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    record_attempt: Callable[[dict[str, Any]], None] | None = None,
    domain_semaphores: dict[str, asyncio.Semaphore] | None = None,
    previous_attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    last_error: BaseException | None = None
    start_index = 0
    if previous_attempts:
        previous = previous_attempts[-1]
        if previous.get("error_type") != "interrupted":
            retryable = (previous.get("error_type") not in {None, "invalid_url"}
                         or previous.get("status_code") in RETRYABLE_STATUS)
            if not retryable or previous["retry_index"] >= settings.retries:
                return previous
            start_index = previous["retry_index"] + 1
        else:
            start_index = previous["retry_index"]
    for attempt in range(start_index, settings.retries + 1):
        started = time.perf_counter()
        attempt_id = uuid.uuid4().hex
        started_at = utc_now()
        if record_attempt:
            record_attempt(dict(phase="started", attempt_id=attempt_id,
                                method=method, started_at=started_at, retry_index=attempt))
        history = []
        response = None
        body = bytearray()
        try:
            current_url = url
            for hop in range(settings.max_redirects + 1):
                domain = (urlsplit(current_url).hostname or "<invalid>").lower()
                semaphore = (domain_semaphores if domain_semaphores is not None else {}).setdefault(
                    domain, asyncio.Semaphore(settings.per_domain)
                )
                response = None
                async with semaphore, client.stream(method, current_url, follow_redirects=False) as response:
                    if response.has_redirect_location:
                        history.append({"status_code": response.status_code,
                                        "url": str(response.url),
                                        "location": response.headers.get("location")})
                        if hop >= settings.max_redirects:
                            raise httpx.TooManyRedirects("Překročen limit redirectů.", request=response.request)
                        current_url = str(response.url.join(response.headers["location"]))
                        continue
                    if method == "GET" and settings.max_body_bytes > 0:
                        async for chunk in response.aiter_bytes():
                            remaining = settings.max_body_bytes - len(body)
                            body.extend(chunk[:remaining])
                            if len(body) >= settings.max_body_bytes:
                                break
                    break
            if response is not None:
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
                content_type = response.headers.get("content-type")
                html_title, fingerprint = body_diagnostics(bytes(body), content_type)
                content_length = response.headers.get("content-length")
                try:
                    parsed_length = int(content_length) if content_length else None
                except ValueError:
                    parsed_length = None
                result = {
                    "status_code": response.status_code,
                    "original_status_code": (
                        history[0]["status_code"]
                        if history
                        else response.status_code
                    ),
                    "final_url": str(response.url),
                    "redirect_count": len(history),
                    "redirect_history_json": json.dumps(history, ensure_ascii=False),
                    "response_time_ms": elapsed_ms,
                    "content_type": content_type,
                    "content_length": parsed_length,
                    "body_bytes_read": len(body),
                    "html_title": html_title,
                    "content_fingerprint": fingerprint,
                    "attempts": attempt + 1,
                    "error_type": None,
                    "error_message": None,
                    "retry_after": response.headers.get("retry-after"),
                }
                if record_attempt:
                    record_attempt(dict(result, phase="completed", attempt_id=attempt_id,
                                        method=method, started_at=started_at, completed_at=utc_now(),
                                        retry_index=attempt))
                if (
                    response.status_code not in RETRYABLE_STATUS
                    or attempt >= settings.retries
                ):
                    return result
                delay = backoff(
                    settings, attempt, response.headers.get("retry-after")
                )
        except (httpx.RequestError, httpx.InvalidURL, ValueError, asyncio.CancelledError) as exc:
            last_error = exc
            result = {
                    "status_code": response.status_code if response is not None else None,
                    "original_status_code": history[0]["status_code"] if history else (response.status_code if response is not None else None),
                    "final_url": str(response.url) if response is not None else current_url,
                    "redirect_count": len(history),
                    "redirect_history_json": json.dumps(history, ensure_ascii=False),
                    "response_time_ms": round(
                        (time.perf_counter() - started) * 1000, 1
                    ),
                    "content_type": None,
                    "content_length": None,
                    "body_bytes_read": len(body),
                    "html_title": None,
                    "content_fingerprint": None,
                    "attempts": attempt + 1,
                    "error_type": (
                        "interrupted"
                        if isinstance(exc, asyncio.CancelledError)
                        else "redirect_error"
                        if history and isinstance(exc, (httpx.InvalidURL, ValueError))
                        else "invalid_url"
                        if isinstance(exc, ValueError)
                        else error_kind(exc)
                    ),
                    "error_message": f"{type(exc).__name__}: {exc}",
                }
            if record_attempt:
                record_attempt(dict(result, phase="completed", attempt_id=attempt_id,
                                    method=method, started_at=started_at, completed_at=utc_now(),
                                    retry_index=attempt))
            if isinstance(exc, asyncio.CancelledError):
                raise
            if attempt >= settings.retries or result["error_type"] in {
                "invalid_url", "redirect_error"
            }:
                return result
            delay = backoff(settings, attempt, None)
        await sleep(delay)
    raise RuntimeError(f"Nedosažitelný stav požadavku: {last_error}")


def needs_get(head: dict[str, Any]) -> bool:
    status = head["status_code"]
    return bool(
        head["error_type"]
        or status in HEAD_GET_FALLBACK
        or (status is not None and status >= 500)
    )


async def check_url(
    client: httpx.AsyncClient,
    url: str,
    settings: Settings,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    record_attempt: Callable[[dict[str, Any]], None] | None = None,
    domain_semaphores: dict[str, asyncio.Semaphore] | None = None,
    load_attempts: Callable[[str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    checked_at = utc_now()
    features = url_features(url)
    validation_error = validate_url(url)
    if validation_error:
        return {
            "url_clean": url,
            "checked_at": checked_at,
            "request_method": None,
            "head_status_code": None,
            "get_status_code": None,
            "original_status_code": None,
            "final_status_code": None,
            "final_url": None,
            "redirect_count": 0,
            "redirect_history_json": "[]",
            "response_time_ms": None,
            "content_type": None,
            "content_length": None,
            "body_bytes_read": 0,
            "html_title": None,
            "content_fingerprint": None,
            "redirect_type": "none",
            "head_attempts": 0,
            "get_attempts": 0,
            "head_error_type": None,
            "head_error_message": None,
            "get_error_type": None,
            "get_error_message": None,
            "error_type": "invalid_url",
            "error_message": validation_error,
            "classification": "invalid_url",
            "classification_version": CLASSIFICATION_VERSION,
            **features,
        }

    head: dict[str, Any] | None = None
    get: dict[str, Any] | None = None
    if settings.request_strategy == "get":
        get = await request_once(client, "GET", url, settings, sleep, record_attempt, domain_semaphores,
                                 load_attempts("GET") if load_attempts else None)
    elif settings.request_strategy == "head-get":
        head = await request_once(client, "HEAD", url, settings, sleep, record_attempt, domain_semaphores,
                                  load_attempts("HEAD") if load_attempts else None)
        if needs_get(head):
            get = await request_once(client, "GET", url, settings, sleep, record_attempt, domain_semaphores,
                                     load_attempts("GET") if load_attempts else None)
    else:
        raise ValueError(f"Neznámá strategie požadavku: {settings.request_strategy!r}")
    final = get or head
    assert final is not None
    return {
        "url_clean": url,
        "checked_at": checked_at,
        "request_method": "GET" if get else "HEAD",
        "head_status_code": head["status_code"] if head else None,
        "get_status_code": get["status_code"] if get else None,
        "original_status_code": final["original_status_code"],
        "final_status_code": final["status_code"],
        "final_url": final["final_url"],
        "redirect_count": final["redirect_count"],
        "redirect_history_json": final["redirect_history_json"],
        "response_time_ms": final["response_time_ms"],
        "content_type": final["content_type"],
        "content_length": final["content_length"],
        "body_bytes_read": final["body_bytes_read"],
        "html_title": final["html_title"],
        "content_fingerprint": final["content_fingerprint"],
        "redirect_type": redirect_type(url, final["final_url"], final["redirect_count"]),
        "head_attempts": head["attempts"] if head else 0,
        "get_attempts": get["attempts"] if get else 0,
        "head_error_type": head["error_type"] if head else None,
        "head_error_message": head["error_message"] if head else None,
        "get_error_type": get["error_type"] if get else None,
        "get_error_message": get["error_message"] if get else None,
        "error_type": final["error_type"],
        "error_message": final["error_message"],
        "classification": classify(
            final["status_code"], final["error_type"], final["redirect_count"]
        ),
        "classification_version": CLASSIFICATION_VERSION,
        **features,
    }


def connect_database(path: Path, read_only: bool = False) -> sqlite3.Connection:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(
            f"Existující SQLite databáze nebyla nalezena: {resolved}"
        )
    if read_only:
        connection = sqlite3.connect(
            f"file:{resolved.as_posix()}?mode=ro", uri=True
        )
    else:
        connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=rw", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def ensure_result_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS http_check_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_name TEXT NOT NULL UNIQUE,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            requested_limit INTEGER NOT NULL,
            status TEXT NOT NULL,
            config_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS http_checks (
            run_id INTEGER NOT NULL,
            url_clean TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            request_method TEXT,
            head_status_code INTEGER,
            get_status_code INTEGER,
            original_status_code INTEGER,
            final_status_code INTEGER,
            final_url TEXT,
            redirect_count INTEGER NOT NULL,
            redirect_history_json TEXT NOT NULL,
            response_time_ms REAL,
            content_type TEXT,
            content_length INTEGER,
            body_bytes_read INTEGER,
            html_title TEXT,
            content_fingerprint TEXT,
            redirect_type TEXT,
            head_attempts INTEGER NOT NULL,
            get_attempts INTEGER NOT NULL,
            head_error_type TEXT,
            head_error_message TEXT,
            get_error_type TEXT,
            get_error_message TEXT,
            error_type TEXT,
            error_message TEXT,
            classification TEXT NOT NULL,
            classification_version TEXT,
            input_quality_class TEXT,
            input_issue_reason TEXT,
            url_host TEXT,
            url_tld TEXT,
            url_scope TEXT,
            path_depth INTEGER,
            PRIMARY KEY (run_id, url_clean),
            FOREIGN KEY (run_id) REFERENCES http_check_runs(run_id)
        );

        CREATE INDEX IF NOT EXISTS idx_http_checks_url_clean
            ON http_checks(url_clean);
        CREATE INDEX IF NOT EXISTS idx_http_checks_classification
            ON http_checks(classification);

        CREATE TABLE IF NOT EXISTS http_check_targets (
            run_id INTEGER NOT NULL,
            selection_order INTEGER NOT NULL,
            url_clean TEXT NOT NULL,
            target_metadata_json TEXT NOT NULL,
            PRIMARY KEY (run_id, url_clean),
            UNIQUE (run_id, selection_order),
            FOREIGN KEY (run_id) REFERENCES http_check_runs(run_id)
        );
        """
    )
    existing_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(http_checks)")
    }
    migrations = {
        "content_length": "INTEGER",
        "body_bytes_read": "INTEGER",
        "html_title": "TEXT",
        "content_fingerprint": "TEXT",
        "redirect_type": "TEXT",
        "classification_version": "TEXT",
        "input_quality_class": "TEXT",
        "input_issue_reason": "TEXT",
        "url_host": "TEXT",
        "url_tld": "TEXT",
        "url_scope": "TEXT",
        "path_depth": "INTEGER",
    }
    for name, sql_type in migrations.items():
        if name not in existing_columns:
            connection.execute(
                f'ALTER TABLE http_checks ADD COLUMN "{name}" {sql_type}'
            )
    connection.commit()
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS http_attempt_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_id TEXT NOT NULL,
            run_id INTEGER NOT NULL REFERENCES http_check_runs(run_id),
            url_clean TEXT NOT NULL,
            method TEXT NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('started', 'completed')),
            recorded_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            UNIQUE(attempt_id, phase)
        );
        CREATE INDEX IF NOT EXISTS idx_attempt_run_url
            ON http_attempt_events(run_id, url_clean, event_id);
        CREATE TRIGGER IF NOT EXISTS attempts_no_update
            BEFORE UPDATE ON http_attempt_events BEGIN
            SELECT RAISE(ABORT, 'HTTP pokusy jsou append-only'); END;
        CREATE TRIGGER IF NOT EXISTS attempts_no_delete
            BEFORE DELETE ON http_attempt_events BEGIN
            SELECT RAISE(ABORT, 'HTTP pokusy jsou append-only'); END;
        CREATE TRIGGER IF NOT EXISTS attempts_no_replace
            BEFORE INSERT ON http_attempt_events
            WHEN EXISTS(SELECT 1 FROM http_attempt_events WHERE
                event_id=NEW.event_id OR (attempt_id=NEW.attempt_id AND phase=NEW.phase))
            BEGIN SELECT RAISE(ABORT, 'HTTP pokusy jsou append-only'); END;
    """)


def save_attempt(connection: sqlite3.Connection, run_id: int, url: str,
                 event: dict[str, Any]) -> None:
    """Samostatný commit před požadavkem a ihned po výsledku, také před backoffem."""
    connection.execute(
        "INSERT INTO http_attempt_events(attempt_id,run_id,url_clean,method,phase,recorded_at,payload_json) "
        "VALUES (?,?,?,?,?,?,?)",
        (event["attempt_id"], run_id, url, event["method"], event["phase"], utc_now(),
         json.dumps(event, ensure_ascii=False, sort_keys=True)),
    )
    connection.commit()


def load_completed_attempts(connection: sqlite3.Connection, run_id: int, url: str,
                            method: str) -> list[dict[str, Any]]:
    return [json.loads(row[0]) for row in connection.execute(
        "SELECT payload_json FROM http_attempt_events WHERE run_id=? AND url_clean=? "
        "AND method=? AND phase='completed' ORDER BY event_id", (run_id, url, method))]


def candidate_urls(
    connection: sqlite3.Connection,
    limit: int,
    selection: str = "first",
    seed: int = 20260728,
    source_run: str | None = None,
    exclude_run: str | None = None,
) -> list[str]:
    if selection == "replicate":
        if not source_run:
            raise ValueError("Výběr replicate vyžaduje --source-run.")
        source = connection.execute(
            "SELECT run_id,status FROM http_check_runs WHERE run_name=?",
            (source_run,),
        ).fetchone()
        if not source or source["status"] != "completed":
            raise ValueError("Zdrojový běh replicate musí existovat a být dokončený.")
        rows = connection.execute(
            """
            SELECT t.url_clean, c.classification,
                   EXISTS(
                       SELECT 1 FROM http_checks f
                       WHERE f.url_clean=t.url_clean
                         AND lower(trim(f.html_title))='web filter violation'
                   ) AS web_filter_violation
            FROM http_check_targets t
            LEFT JOIN http_checks c
              ON c.run_id=t.run_id AND c.url_clean=t.url_clean
            WHERE t.run_id=?
            ORDER BY t.selection_order
            """,
            (source["run_id"],),
        ).fetchall()
        if any(row["classification"] is None for row in rows):
            raise ValueError("Zdrojový běh replicate nemá výsledek pro každý cíl.")
        total = len(rows)
        if limit == total:
            # Úplná replikace zachovává přesně pořadí a tím i hash zdrojového panelu.
            return [row["url_clean"] for row in rows]
        if limit > 20:
            raise ValueError(
                f"Replicate dovoluje jen pilot nejvýše 20 URL nebo celý panel "
                f"{total} URL; obdrženo {limit}."
            )
        if limit > total:
            raise ValueError(f"Zdrojový běh obsahuje jen {total} cílů.")

        ranked = sorted(
            rows,
            key=lambda row: hashlib.sha256(
                f"{seed}\0{row['url_clean']}".encode("utf-8")
            ).digest(),
        )
        selected: list[str] = []
        selected_hosts: set[str] = set()

        def add_distinct(candidates: list[sqlite3.Row], wanted: int) -> None:
            for row in candidates:
                if len(selected) >= wanted:
                    return
                url = row["url_clean"]
                host = (urlsplit(url).hostname or "").lower()
                if url not in selected and host not in selected_hosts:
                    selected.append(url)
                    selected_hosts.add(host)

        # Polovina pilotu cílí na historické blokovací stránky; druhá polovina
        # pokrývá běžné klasifikace zdrojového běhu jako kontrolní skupinu.
        focus_target = limit // 2
        focus = [row for row in ranked if row["web_filter_violation"]]
        add_distinct(focus, focus_target)
        for row in focus:
            if len(selected) >= focus_target:
                break
            if row["url_clean"] not in selected:
                selected.append(row["url_clean"])
                selected_hosts.add((urlsplit(row["url_clean"]).hostname or "").lower())

        groups: dict[str, list[sqlite3.Row]] = {}
        for row in ranked:
            if not row["web_filter_violation"]:
                groups.setdefault(row["classification"], []).append(row)
        for classification in sorted(groups):
            add_distinct(groups[classification], len(selected) + 1)
            if len(selected) == limit:
                return selected
        add_distinct(ranked, limit)
        for row in ranked:
            if len(selected) == limit:
                return selected
            if row["url_clean"] not in selected:
                selected.append(row["url_clean"])
        return selected
    if selection == "wave2":
        if not source_run:
            raise ValueError("Výběr wave2 vyžaduje --source-run.")
        source = connection.execute(
            "SELECT run_id,status FROM http_check_runs WHERE run_name=?",
            (source_run,),
        ).fetchone()
        if not source or source["status"] != "completed":
            raise ValueError("Zdrojový běh wave2 musí existovat a být dokončený.")
        rows = connection.execute(
            """
            SELECT c.url_clean,c.classification
            FROM http_checks c
            JOIN http_check_targets t
              ON t.run_id=c.run_id AND t.url_clean=c.url_clean
            WHERE c.run_id=? AND c.classification<>'invalid_url'
            ORDER BY t.selection_order
            """,
            (source["run_id"],),
        ).fetchall()
        total = len(rows)
        if limit > 20 and limit != total:
            raise ValueError(
                f"Wave2 dovoluje jen pilot nejvýše 20 URL nebo celý validní "
                f"soubor {total} URL; obdrženo {limit}."
            )
        ranked = sorted(
            ((row["url_clean"], row["classification"]) for row in rows),
            key=lambda item: hashlib.sha256(
                f"{seed}\0{item[0]}".encode("utf-8")
            ).digest(),
        )
        if limit == total:
            return [url for url, _ in ranked]
        groups: dict[str, list[str]] = {}
        for url, classification in ranked:
            groups.setdefault(classification, []).append(url)
        selected: list[str] = []
        selected_hosts: set[str] = set()
        # Jeden cíl z každé historické kategorie; pokud možno různé hostname.
        for classification in sorted(groups):
            candidates = groups[classification]
            chosen = next(
                (url for url in candidates
                 if (urlsplit(url).hostname or "").lower() not in selected_hosts),
                candidates[0],
            )
            selected.append(chosen)
            selected_hosts.add((urlsplit(chosen).hostname or "").lower())
            if len(selected) == limit:
                return selected
        # Zbytek je deterministický hashovaný vzorek napříč celým univerzem.
        for url, _ in ranked:
            host = (urlsplit(url).hostname or "").lower()
            if url not in selected and host not in selected_hosts:
                selected.append(url)
                selected_hosts.add(host)
                if len(selected) == limit:
                    return selected
        for url, _ in ranked:
            if url not in selected:
                selected.append(url)
                if len(selected) == limit:
                    return selected
        raise ValueError(f"Pro wave2 je dostupných jen {len(selected)} URL.")
    if selection == "corrected":
        if __package__:
            from .url_corrections import pilot_candidates
        else:
            from url_corrections import pilot_candidates
        return pilot_candidates(connection, source_run, limit)
    if selection == "corrected_unchecked":
        if not source_run or not exclude_run:
            raise ValueError(
                "Výběr corrected_unchecked vyžaduje --source-run a --exclude-run."
            )
        if __package__:
            from .url_corrections import unchecked_corrected_candidates
        else:
            from url_corrections import unchecked_corrected_candidates
        urls = unchecked_corrected_candidates(connection, source_run, exclude_run)
        if limit != len(urls):
            raise ValueError(
                f"Plný korekční běh musí mít přesný limit {len(urls)}, "
                f"obdrženo {limit}."
            )
        return urls
    query = """
        WITH occurrences AS (
            SELECT 1 AS source_order, rowid AS source_row, url_clean FROM url_ok
            UNION ALL
            SELECT 2, rowid, url_clean FROM url_podezrele_vycistene
            UNION ALL
            SELECT 3, rowid, url_clean FROM url_odmitnute_vycistene
        ),
        first_seen AS (
            SELECT
                url_clean,
                MIN(source_order * 1000000000 + source_row) AS first_position
            FROM occurrences
            WHERE url_clean IS NOT NULL AND TRIM(url_clean) <> ''
            GROUP BY url_clean
        )
        SELECT url_clean
        FROM first_seen
        ORDER BY first_position
    """
    urls = [row[0] for row in connection.execute(query)]
    if selection == "all":
        if limit != len(urls):
            raise ValueError(
                f"Plný běh musí mít limit přesně {len(urls)}, obdrženo {limit}."
            )
        return urls
    if selection == "first":
        return urls[:limit]
    if selection == "random":
        if limit > len(urls):
            raise ValueError(
                f"Požadovaný vzorek {limit} je větší než počet URL {len(urls)}."
            )
        return random.Random(seed).sample(urls, limit)
    if selection == "stratified":
        rows = connection.execute(
            """
            WITH occurrences AS (
                SELECT 'OK' source_name, url_clean, document_id, metoda FROM url_ok
                UNION ALL
                SELECT 'PODEZRELE', url_clean, document_id, metoda FROM url_podezrele_vycistene
                UNION ALL
                SELECT 'ODMITNUTO', url_clean, document_id, metoda FROM url_odmitnute_vycistene
            )
            SELECT o.url_clean,
                   MIN(o.source_name),
                   GROUP_CONCAT(DISTINCT o.metoda),
                   MIN(SUBSTR(m.datum_obhajoby, 1, 4)),
                   MIN(m.obor)
            FROM occurrences o
            LEFT JOIN mff_metadata m ON m.document_id = o.document_id
            WHERE o.url_clean IS NOT NULL AND TRIM(o.url_clean) <> ''
            GROUP BY o.url_clean
            """
        ).fetchall()
        groups: dict[tuple[str, str, str, str, str], list[str]] = {}
        for url, source, methods, year, obor in rows:
            features = url_features(url)
            method_class = "both" if methods and "," in methods else (methods or "unknown")
            year_group = year if year and year.isdigit() else "unknown"
            key = (
                source or "unknown",
                year_group,
                method_class,
                features["url_scope"] or "unknown",
                features["input_quality_class"],
            )
            groups.setdefault(key, []).append(url)
        rng = random.Random(seed)
        keys = sorted(groups)
        rng.shuffle(keys)
        for values in groups.values():
            rng.shuffle(values)
        selected: list[str] = []
        while len(selected) < limit and keys:
            remaining = []
            for key in keys:
                values = groups[key]
                if values and len(selected) < limit:
                    selected.append(values.pop())
                if values:
                    remaining.append(key)
            keys = remaining
        if len(selected) < limit:
            raise ValueError(f"Pro stratifikovaný výběr je dostupných jen {len(selected)} URL.")
        return selected
    if selection == "retryable":
        if not source_run:
            raise ValueError("Výběr retryable vyžaduje --source-run.")
        placeholders = ",".join("?" for _ in UNCERTAIN_CLASSIFICATIONS)
        rows = connection.execute(
            f"""
            SELECT c.url_clean
            FROM http_checks c
            JOIN http_check_runs r ON r.run_id = c.run_id
            WHERE r.run_name = ? AND c.classification IN ({placeholders})
            ORDER BY c.url_clean
            """,
            (source_run, *sorted(UNCERTAIN_CLASSIFICATIONS)),
        ).fetchall()
        retry_urls = [row[0] for row in rows]
        if limit > len(retry_urls):
            raise ValueError(
                f"Zdrojový běh obsahuje jen {len(retry_urls)} nejistých URL."
            )
        return retry_urls[:limit]
    raise ValueError(f"Neznámý způsob výběru URL: {selection!r}")


def frozen_targets(connection: sqlite3.Connection, run_id: int) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT url_clean FROM http_check_targets WHERE run_id=? ORDER BY selection_order",
            (run_id,),
        )
    ]


def freeze_targets(connection: sqlite3.Connection, run_id: int, urls: list[str]) -> None:
    config = json.loads(connection.execute(
        "SELECT config_json FROM http_check_runs WHERE run_id=?", (run_id,)).fetchone()[0])
    rows = []
    for order, url in enumerate(urls, start=1):
        metadata = {**url_features(url), "selection_version": SELECTION_VERSION}
        if config.get("selection") in {"corrected", "corrected_unchecked"}:
            metadata["correction_ids"] = [row[0] for row in connection.execute(
                "SELECT correction_id FROM url_corrections WHERE normalized_url=? AND rule_version=? "
                "AND correction_id IN (SELECT correction_id FROM url_correction_effective WHERE effective_eligible=1) "
                "AND source_run_id=(SELECT run_id FROM http_check_runs WHERE run_name=?) "
                "ORDER BY correction_id", (url, config["correction_version"], config["source_run"]))]
        rows.append((run_id, order, url, json.dumps(metadata, ensure_ascii=False, sort_keys=True)))
    connection.executemany(
        "INSERT INTO http_check_targets(run_id, selection_order, url_clean, target_metadata_json) VALUES (?, ?, ?, ?)",
        rows,
    )
    config["target_count"] = len(urls)
    config["target_sha256"] = hashlib.sha256("\n".join(urls).encode("utf-8")).hexdigest()
    connection.execute("UPDATE http_check_runs SET config_json=? WHERE run_id=?",
                       (json.dumps(config, ensure_ascii=False, sort_keys=True), run_id))
    connection.commit()


def get_or_create_run(
    connection: sqlite3.Connection,
    run_name: str,
    limit: int,
    settings: Settings,
    selection: str = "first",
    seed: int = 20260728,
    source_run: str | None = None,
    exclude_run: str | None = None,
) -> int:
    run_config = {
        **settings.__dict__,
        "selection": selection,
        "selection_seed": seed,
        "selection_version": SELECTION_VERSION,
        "classification_version": CLASSIFICATION_VERSION,
        "engine_version": ENGINE_VERSION,
        "source_run": source_run,
        "exclude_run": exclude_run,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "httpx_version": httpx.__version__,
        "idna_version": idna.__version__,
        "python_version": sys.version,
        "openssl_version": ssl.OPENSSL_VERSION,
        "retryable_status": sorted(RETRYABLE_STATUS),
        "head_get_fallback": sorted(HEAD_GET_FALLBACK),
        "trust_env": False,
    }
    if selection in {"corrected", "corrected_unchecked"}:
        if __package__:
            from .url_corrections import VERSION, correction_digest
        else:
            from url_corrections import VERSION, correction_digest
        run_config["correction_version"] = VERSION
        run_config["correction_sha256"] = correction_digest(connection, source_run)
        run_config["correction_script_sha256"] = hashlib.sha256(
            Path(__file__).with_name("url_corrections.py").read_bytes()).hexdigest()
    existing = connection.execute(
        "SELECT run_id, requested_limit, config_json FROM http_check_runs WHERE run_name=?",
        (run_name,),
    ).fetchone()
    if existing:
        if existing["requested_limit"] != limit:
            raise ValueError(
                f"Běh {run_name!r} už existuje s limitem "
                f"{existing['requested_limit']}, nikoli {limit}."
            )
        config = json.loads(existing["config_json"])
        ignored = {"resume_events", "target_count", "target_sha256"}
        previous = {key: value for key, value in config.items() if key not in ignored}
        differences = sorted(key for key in set(previous) | set(run_config)
                             if previous.get(key) != run_config.get(key)
                             or (key in previous) != (key in run_config))
        if differences:
            raise ValueError("Resume odmítnuto, odlišná konfigurace: " + ", ".join(differences))
        targets = frozen_targets(connection, existing["run_id"])
        if (targets or "target_count" in config) and (config.get("target_count") != len(targets) or
                        config.get("target_sha256") != hashlib.sha256("\n".join(targets).encode()).hexdigest()):
            raise ValueError("Resume odmítnuto: změněné nebo neauditované zmrazené cíle.")
        config.setdefault("resume_events", []).append(
            {
                "resumed_at": utc_now(),
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            }
        )
        connection.execute(
            "UPDATE http_check_runs SET status='running', completed_at=NULL, config_json=? "
            "WHERE run_id=?",
            (json.dumps(config, ensure_ascii=False, sort_keys=True), existing["run_id"]),
        )
        connection.commit()
        return int(existing["run_id"])
    cursor = connection.execute(
        """
        INSERT INTO http_check_runs
            (run_name, started_at, requested_limit, status, config_json)
        VALUES (?, ?, ?, 'running', ?)
        """,
        (
            run_name,
            utc_now(),
            limit,
            json.dumps(run_config, ensure_ascii=False, sort_keys=True),
        ),
    )
    connection.commit()
    return int(cursor.lastrowid)


RESULT_COLUMNS = (
    "url_clean",
    "checked_at",
    "request_method",
    "head_status_code",
    "get_status_code",
    "original_status_code",
    "final_status_code",
    "final_url",
    "redirect_count",
    "redirect_history_json",
    "response_time_ms",
    "content_type",
    "content_length",
    "body_bytes_read",
    "html_title",
    "content_fingerprint",
    "redirect_type",
    "head_attempts",
    "get_attempts",
    "head_error_type",
    "head_error_message",
    "get_error_type",
    "get_error_message",
    "error_type",
    "error_message",
    "classification",
    "classification_version",
    "input_quality_class",
    "input_issue_reason",
    "url_host",
    "url_tld",
    "url_scope",
    "path_depth",
)


def save_result(
    connection: sqlite3.Connection, run_id: int, result: dict[str, Any]
) -> None:
    columns = ("run_id",) + RESULT_COLUMNS
    placeholders = ",".join("?" for _ in columns)
    connection.execute(
        f"INSERT INTO http_checks ({','.join(columns)}) "
        f"VALUES ({placeholders})",
        [run_id] + [result.get(column) for column in RESULT_COLUMNS],
    )
    connection.commit()


async def run_checks(
    database: Path,
    run_name: str,
    limit: int,
    settings: Settings,
    selection: str = "first",
    seed: int = 20260728,
    source_run: str | None = None,
    exclude_run: str | None = None,
) -> int:
    if selection == "corrected" and not 1 <= limit <= 20:
        raise ValueError("Korekční běh je zatím omezen na pilot 1–20 URL.")
    connection = connect_database(database)
    ensure_result_schema(connection)
    run_id = get_or_create_run(
        connection, run_name, limit, settings, selection, seed, source_run,
        exclude_run
    )
    selected = frozen_targets(connection, run_id)
    if not selected:
        selected = candidate_urls(
            connection, limit, selection, seed, source_run=source_run,
            exclude_run=exclude_run
        )
        freeze_targets(connection, run_id, selected)
    completed = {
        row[0]
        for row in connection.execute(
            "SELECT url_clean FROM http_checks WHERE run_id=?", (run_id,)
        )
    }
    pending = [url for url in selected if url not in completed]
    print(
        f"Běh {run_name!r}: vybráno {len(selected)}, "
        f"hotovo {len(completed)}, zbývá {len(pending)}.",
        flush=True,
    )
    if not pending:
        connection.execute(
            "UPDATE http_check_runs SET status='completed', completed_at=? "
            "WHERE run_id=?",
            (utc_now(), run_id),
        )
        connection.commit()
        connection.close()
        return run_id

    timeout = httpx.Timeout(
        connect=settings.connect_timeout,
        read=settings.read_timeout,
        write=settings.write_timeout,
        pool=settings.pool_timeout,
    )
    limits = httpx.Limits(
        max_connections=settings.concurrency,
        max_keepalive_connections=settings.concurrency,
    )
    global_semaphore = asyncio.Semaphore(settings.concurrency)
    domain_semaphores: dict[str, asyncio.Semaphore] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        max_redirects=settings.max_redirects,
        headers={"User-Agent": settings.user_agent, "Accept": "*/*"},
        trust_env=False,
    ) as client:

        async def limited(url: str) -> dict[str, Any]:
            async with global_semaphore:
                return await check_url(client, url, settings,
                    record_attempt=lambda event: save_attempt(connection, run_id, url, event),
                    domain_semaphores=domain_semaphores,
                    load_attempts=lambda method: load_completed_attempts(connection, run_id, url, method))

        queue: asyncio.Queue[str] = asyncio.Queue()
        for url in pending:
            queue.put_nowait(url)

        async def worker() -> None:
            while True:
                try:
                    url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    result = await limited(url)
                    save_result(connection, run_id, result)
                    completed_count = connection.execute(
                        "SELECT COUNT(*) FROM http_checks WHERE run_id=?", (run_id,)
                    ).fetchone()[0]
                    print(
                        f"[{completed_count}/{len(selected)}] "
                        f"{result['classification']}: {result['url_clean']}",
                        flush=True,
                    )
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(settings.concurrency)]
        try:
            await asyncio.gather(*workers)
        except BaseException:
            for worker_task in workers:
                worker_task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            connection.execute(
                "UPDATE http_check_runs SET status='interrupted' WHERE run_id=?",
                (run_id,),
            )
            connection.commit()
            raise

    connection.execute(
        "UPDATE http_check_runs SET status='completed', completed_at=? "
        "WHERE run_id=?",
        (utc_now(), run_id),
    )
    connection.commit()
    connection.close()
    return run_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asynchronní a obnovitelná kontrola URL v existující SQLite DB."
    )
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--database", type=Path, default=DATABASE)
    parser.add_argument("--run-name", default="pilot20")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument(
        "--allow-large-run",
        action="store_true",
        help="Povolí více než 20 URL; použít jen po výslovném souhlasu.",
    )
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--per-domain", type=int)
    parser.add_argument("--max-body-bytes", type=int)
    parser.add_argument(
        "--request-strategy",
        choices=("get", "head-get"),
        help="Výchozí get používá omezený streamovaný GET; head-get je historický režim.",
    )
    parser.add_argument(
        "--selection",
        choices=("first", "random", "stratified", "all", "retryable", "corrected", "corrected_unchecked", "wave2", "replicate"),
        default="first",
        help="Způsob zmrazení cílové množiny URL.",
    )
    parser.add_argument("--seed", type=int, default=20260728)
    parser.add_argument("--source-run", help="Zdrojový běh pro odvozený výběr.")
    parser.add_argument(
        "--exclude-run",
        help="Dokončený běh, jehož již změřené URL výběr corrected_unchecked vynechá.",
    )
    return parser


def settings_from_config(path: Path, args: argparse.Namespace) -> Settings:
    values: dict[str, Any] = {}
    if path.exists():
        values = json.loads(path.read_text(encoding="utf-8"))
    allowed = set(Settings.__dataclass_fields__)
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Neznámé položky konfigurace: {sorted(unknown)}")
    if args.concurrency is not None:
        values["concurrency"] = args.concurrency
    if args.per_domain is not None:
        values["per_domain"] = args.per_domain
    if args.max_body_bytes is not None:
        values["max_body_bytes"] = args.max_body_bytes
    if args.request_strategy is not None:
        values["request_strategy"] = args.request_strategy
    return Settings(**values)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    args = build_parser().parse_args()
    if args.limit < 1:
        raise SystemExit("--limit musí být kladné číslo.")
    if args.limit > 20 and not args.allow_large_run:
        raise SystemExit(
            "Více než 20 URL je zablokováno. Po výslovném souhlasu použijte "
            "--allow-large-run."
        )
    settings = settings_from_config(args.config, args)
    if settings.concurrency < 1 or settings.per_domain < 1:
        raise SystemExit("Limity souběžnosti musí být kladné.")
    if settings.max_body_bytes < 0:
        raise SystemExit("--max-body-bytes nesmí být záporné.")
    asyncio.run(
        run_checks(
            args.database,
            args.run_name,
            args.limit,
            settings,
            selection=args.selection,
            seed=args.seed,
            source_run=args.source_run,
            exclude_run=args.exclude_run,
        )
    )


if __name__ == "__main__":
    main()
