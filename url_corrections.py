"""Odvozené korekce url_clean; příprava nemění vstupy ani historická měření."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import sys
from urllib.parse import urlsplit, urlunsplit

import httpx
import idna

if __package__:
    from .url_http_check import connect_database, utc_now, URL_TABLES
else:
    from url_http_check import connect_database, utc_now, URL_TABLES

VERSION = "2026-09-05-v1"
LIGATURES = str.maketrans(dict(zip("ﬀﬁﬂﬃﬄﬅﬆ", ("ff", "fi", "fl", "ffi", "ffl", "st", "st"))))
ZERO_WIDTH = "\u200b\ufeff"


def validate_candidate(url: str) -> str | None:
    """Striktní syntax, port a IDNA; HTTP úspěch není součástí validace."""
    try:
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
            return "Bílé nebo řídicí znaky."
        if re.search(r"%(?![0-9a-fA-F]{2})", url):
            return "Neplatné percent-encoding."
        if any(c in url for c in '\\<>"{}|'):
            return "Nepovolený syntaktický znak."
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return "Chybí HTTP(S) schéma nebo hostname."
        if parsed.username is not None or parsed.password is not None:
            return "Userinfo vyžaduje ruční posouzení."
        parsed.port
        if ":" in parsed.hostname:
            ipaddress.IPv6Address(parsed.hostname)
        else:
            idna.encode(parsed.hostname.lower(), uts46=False)
        if any(c in (parsed.path + parsed.query + parsed.fragment) for c in "[]"):
            return "Zbývající hranaté závorky mimo authority."
        httpx.URL(url)
    except (ValueError, idna.IDNAError, httpx.InvalidURL) as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def normalized_url(url: str) -> str:
    """Konzervativní klíč: HTTPX serializace a odstranění fragmentu bez síťového významu."""
    return str(httpx.URL(url).copy_with(fragment=None))


def propose(original: str) -> dict:
    url = original
    steps = []
    confidence = "high"

    def change(new: str, rule: str, reason: str, certainty: str = "high") -> None:
        nonlocal url, confidence
        if new != url:
            steps.append(dict(rule=rule, version=VERSION, before=url, after=new,
                              reason=reason, confidence=certainty))
            url = new
            if certainty != "high":
                confidence = certainty

    change(url.translate({ord(c): None for c in ZERO_WIDTH}), "zero_width",
           "Odstranění explicitních extrakčních znaků U+200B a U+FEFF.")
    # Authority oddělíme lexikálně ještě před urlsplit, který vadné závorky odmítá.
    match = re.match(r"^(https?://)([^/?#]*)(.*)$", url, re.I | re.S)
    if match:
        prefix, authority, tail = match.groups()
        if "[" not in authority and "]" not in authority and "@" not in authority:
            host, colon, port = authority.partition(":")
            fixed = host.translate(LIGATURES) + colon + port
            change(prefix + fixed + tail, "hostname_ligature",
                   "Rozvinutí typografické ligatury výhradně v hostname.")
        match = re.match(r"^(https?://)([^/?#]*)(.*)$", url, re.I | re.S)
        prefix, authority, tail = match.groups()
        if authority.lower() == "adsabs.harvard.edu" or re.fullmatch(r"adsabs\.harvard\.edu:\d+", authority, re.I):
            change(prefix + authority + tail.replace("{%}26", "%26"), "adsabs_percent26",
                   "Doložený artefakt ADS {%}26 → %26; ostatní percent-encoding beze změny.")
            tail = url[len(prefix + authority):]
        token = re.search(r"\[([^\[\]]+)\]$", tail)
        if token:
            # Query/fragment může legitimně obsahovat parametr s hodnotou [x].
            certain = ("?" not in tail and "#" not in tail
                       and re.fullmatch(r"(?:\d+(?:\s*[,;–-]\s*\d+)*|x)", token[1], re.I))
            change(prefix + authority + tail[:token.start()], "trailing_citation_token",
                   "Odstranění celého koncového tokenu včetně obsahu; authority je chráněna.",
                   "high" if certain else "medium")
        elif tail.endswith(("[", "]")):
            end = tail[-1]
            rest = tail[:-1]
            # Osamocená závorka: předchozí část musí mít vyvážené páry.
            balance = 0
            balanced = True
            for char in rest:
                balance += (char == "[") - (char == "]")
                if balance < 0:
                    balanced = False
            if balanced and balance == 0:
                change(prefix + authority + rest, "trailing_unbalanced_bracket",
                       f"Odstranění osamocené koncové {end}; authority je chráněna.",
                       "medium" if "?" in tail or "#" in tail else "high")
    error = validate_candidate(url)
    # Více schémat může být legitimní parametr, ale není jednoznačná automatická oprava.
    if len(re.findall(r"https?://", url, re.I)) > 1 or "|" in url:
        bucket = "manual_glued_url"
    elif any(ord(c) < 32 or ord(c) == 127 for c in url):
        bucket = "manual_control_character"
    elif any(c.isspace() for c in url):
        bucket = "manual_whitespace_or_text"
    else:
        try:
            urlsplit(url).port
            bad_port = False
        except ValueError as exc:
            bad_port = "port" in str(exc).lower()
        if bad_port:
            bucket = "manual_port"
        elif error:
            bucket = "manual_syntax_or_hostname"
        elif steps and confidence == "high":
            bucket = "auto_repairable"
        elif steps:
            bucket = "manual_ambiguous_token"
        else:
            bucket = "manual_no_rule"
    return dict(original_url=original, proposed_url=url if steps else None,
                normalized_url=normalized_url(url) if not error and steps else None,
                rule_version=VERSION, rules_json=json.dumps(steps, ensure_ascii=False, sort_keys=True),
                reason="; ".join(s["reason"] for s in steps) or "Není doložena jednoznačná oprava.",
                confidence=confidence if steps else "low", repairability=bucket,
                validation_error=error, review_status="not_reviewed",
                auto_eligible=int(bucket == "auto_repairable"))


def ensure_schema(c: sqlite3.Connection) -> None:
    c.executescript("""
        CREATE TABLE IF NOT EXISTS url_corrections (
            correction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_run_id INTEGER NOT NULL REFERENCES http_check_runs(run_id),
            original_url TEXT NOT NULL, proposed_url TEXT, normalized_url TEXT,
            rule_version TEXT NOT NULL, rules_json TEXT NOT NULL, reason TEXT NOT NULL,
            confidence TEXT NOT NULL, repairability TEXT NOT NULL, validation_error TEXT,
            review_status TEXT NOT NULL, auto_eligible INTEGER NOT NULL,
            original_classification TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(source_run_id, original_url, rule_version)
        );
        CREATE INDEX IF NOT EXISTS idx_correction_normalized ON url_corrections(normalized_url);
        CREATE TABLE IF NOT EXISTS url_correction_reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            correction_id INTEGER NOT NULL REFERENCES url_corrections(correction_id),
            decision TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
            reviewed_at TEXT NOT NULL, reviewed_by TEXT NOT NULL, reason TEXT NOT NULL
        );
    """)
    for operation in ("UPDATE", "DELETE"):
        c.execute(f"CREATE TRIGGER IF NOT EXISTS corrections_no_{operation.lower()} "
                  f"BEFORE {operation} ON url_corrections BEGIN "
                  "SELECT RAISE(ABORT, 'Korekce jsou append-only'); END")
        c.execute(f"CREATE TRIGGER IF NOT EXISTS correction_reviews_no_{operation.lower()} "
                  f"BEFORE {operation} ON url_correction_reviews BEGIN "
                  "SELECT RAISE(ABORT, 'Rozhodnutí o korekcích jsou append-only'); END")
    c.execute("""CREATE TRIGGER IF NOT EXISTS corrections_no_replace BEFORE INSERT ON url_corrections
        WHEN EXISTS(SELECT 1 FROM url_corrections WHERE correction_id=NEW.correction_id OR
            (source_run_id=NEW.source_run_id AND original_url=NEW.original_url AND rule_version=NEW.rule_version))
        BEGIN SELECT RAISE(ABORT, 'Korekce jsou append-only'); END""")
    c.execute("""CREATE TRIGGER IF NOT EXISTS correction_reviews_no_replace BEFORE INSERT ON url_correction_reviews
        WHEN EXISTS(SELECT 1 FROM url_correction_reviews WHERE review_id=NEW.review_id)
        BEGIN SELECT RAISE(ABORT, 'Rozhodnutí o korekcích jsou append-only'); END""")
    union = " UNION ALL ".join(
        f"SELECT '{table}' source_table, rowid source_rowid, document_id, metoda, url_clean FROM {table}"
        for table in URL_TABLES)
    c.execute(f"""CREATE VIEW IF NOT EXISTS url_correction_occurrences AS
        SELECT k.correction_id, k.source_run_id, k.rule_version, k.original_url,
               k.normalized_url, k.auto_eligible, o.source_table, o.source_rowid, o.document_id, o.metoda
        FROM url_corrections k JOIN ({union}) o ON o.url_clean=k.original_url""")
    c.execute("DROP VIEW IF EXISTS url_correction_citations")
    c.execute("DROP VIEW IF EXISTS url_correction_effective")
    c.execute("""CREATE VIEW url_correction_effective AS
        WITH latest AS (
            SELECT r.* FROM url_correction_reviews r
            WHERE r.review_id=(SELECT MAX(r2.review_id) FROM url_correction_reviews r2
                               WHERE r2.correction_id=r.correction_id)
        )
        SELECT k.*, latest.decision AS review_decision,
               CASE WHEN k.validation_error IS NULL AND k.normalized_url IS NOT NULL
                          AND (k.auto_eligible=1 OR latest.decision='approved')
                    THEN 1 ELSE 0 END AS effective_eligible
        FROM url_corrections k LEFT JOIN latest ON latest.correction_id=k.correction_id""")
    c.execute("""CREATE VIEW url_correction_citations AS
        SELECT source_run_id, rule_version, document_id, normalized_url,
            CASE WHEN MAX(metoda IN ('klikaci_odkaz','klikací_odkaz'))=1
                      AND MAX(metoda IN ('text','text_pres_newline'))=1 THEN 'both'
                 WHEN MAX(metoda IN ('klikaci_odkaz','klikací_odkaz'))=1 THEN 'clickable_only'
                 ELSE 'text_only' END method_class,
            COUNT(*) detection_count, COUNT(DISTINCT original_url) original_url_count
        FROM url_correction_occurrences o
        WHERE EXISTS(SELECT 1 FROM url_correction_effective e
                     WHERE e.correction_id=o.correction_id AND e.effective_eligible=1)
        GROUP BY source_run_id,rule_version,document_id,normalized_url""")
    c.commit()


def source_id(c: sqlite3.Connection, source_run: str) -> int:
    row = c.execute("SELECT run_id,status FROM http_check_runs WHERE run_name=?", (source_run,)).fetchone()
    if not row or row["status"] != "completed":
        raise ValueError("Zdrojový běh musí existovat a být dokončený.")
    return row["run_id"]


def prepare(c: sqlite3.Connection, source_run: str) -> dict:
    run_id = source_id(c, source_run)
    ensure_schema(c)
    rows = c.execute("SELECT url_clean,classification FROM http_checks WHERE run_id=? ORDER BY url_clean",
                     (run_id,)).fetchall()
    for row in rows:
        item = propose(row["url_clean"])
        if row["classification"] != "invalid_url" and item["proposed_url"] is None:
            continue
        old = c.execute("SELECT * FROM url_corrections WHERE source_run_id=? AND original_url=? AND rule_version=?",
                        (run_id, row["url_clean"], VERSION)).fetchone()
        if old:
            if any(old[key] != value for key, value in item.items()):
                raise ValueError("Stejná verze pravidel vytvořila odlišnou korekci; zvyšte verzi.")
            continue
        item.update(source_run_id=run_id, original_classification=row["classification"], created_at=utc_now())
        c.execute(f"INSERT INTO url_corrections({','.join(item)}) VALUES ({','.join('?' for _ in item)})", tuple(item.values()))
        c.commit()
    return summary(c, source_run)


def summary(c: sqlite3.Connection, source_run: str) -> dict:
    run_id = source_id(c, source_run)
    where = "source_run_id=? AND rule_version=?"
    params = (run_id, VERSION)
    invalid = dict(c.execute(f"SELECT repairability,COUNT(*) FROM url_corrections WHERE {where} "
                            "AND original_classification='invalid_url' GROUP BY repairability", params))
    return dict(source_run=source_run, correction_version=VERSION, invalid_url=invalid,
                corrections=c.execute(f"SELECT COUNT(*) FROM url_corrections WHERE {where}", params).fetchone()[0],
                auto_mappings=c.execute(f"SELECT COUNT(*) FROM url_corrections WHERE {where} AND auto_eligible=1", params).fetchone()[0],
                unique_targets=c.execute(f"SELECT COUNT(DISTINCT normalized_url) FROM url_corrections WHERE {where} AND auto_eligible=1", params).fetchone()[0],
                citations=c.execute(f"SELECT COUNT(*) FROM url_correction_citations WHERE {where}", params).fetchone()[0],
                detections=c.execute(f"SELECT COUNT(*) FROM url_correction_occurrences WHERE {where} AND auto_eligible=1", params).fetchone()[0])


def correction_digest(c: sqlite3.Connection, source_run: str) -> str:
    rows = [dict(row) for row in c.execute("SELECT * FROM url_corrections WHERE source_run_id=? AND rule_version=? ORDER BY original_url",
                                          (source_id(c, source_run), VERSION))]
    if not rows:
        raise ValueError("Nejprve připravte korekční vrstvu.")
    reviews = [dict(row) for row in c.execute("""
        SELECT r.* FROM url_correction_reviews r JOIN url_corrections k
          ON k.correction_id=r.correction_id
        WHERE k.source_run_id=? AND k.rule_version=? ORDER BY r.review_id
    """, (source_id(c, source_run), VERSION))]
    payload = {"corrections": rows, "reviews": reviews}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def pilot_candidates(c: sqlite3.Connection, source_run: str, limit: int) -> list[str]:
    if not 1 <= limit <= 20:
        raise ValueError("Korekční výběr je zatím omezen na pilot 1–20 URL.")
    rows = c.execute("SELECT normalized_url,rules_json FROM url_correction_effective "
                     "WHERE source_run_id=? AND rule_version=? AND effective_eligible=1 ORDER BY normalized_url,original_url",
                     (source_id(c, source_run), VERSION)).fetchall()
    groups = defaultdict(list)
    seen = set()
    for row in rows:
        url = row["normalized_url"]
        if url in seen:
            continue
        seen.add(url)
        if validate_candidate(url):
            raise ValueError("Uložený kandidát neprošel validací.")
        rules = "+".join(step["rule"] for step in json.loads(row["rules_json"]))
        groups[rules].append(url)
    selected = []
    # Deterministicky střídat pravidla; nejvýše dvě URL z hostu v první vrstvě.
    host_counts = Counter()
    for cap in (2, limit):
        while len(selected) < limit:
            changed = False
            for key in sorted(groups):
                for url in groups[key]:
                    host = urlsplit(url).hostname
                    if url not in selected and host_counts[host] < cap:
                        selected.append(url)
                        host_counts[host] += 1
                        changed = True
                        break
                if len(selected) == limit:
                    return selected
            if not changed:
                break
    if len(selected) < limit:
        raise ValueError(f"Dostupných jen {len(selected)} opravených URL.")
    return selected


def unchecked_corrected_candidates(
    c: sqlite3.Connection, source_run: str, exclude_run: str
) -> list[str]:
    """Vrátí všechny validní opravené cíle bez výsledku ve zvoleném HTTP běhu."""
    excluded = c.execute(
        "SELECT run_id,status FROM http_check_runs WHERE run_name=?", (exclude_run,)
    ).fetchone()
    if not excluded or excluded["status"] != "completed":
        raise ValueError("Vylučovaný HTTP běh musí existovat a být dokončený.")
    rows = c.execute(
        """
        SELECT DISTINCT e.normalized_url
        FROM url_correction_effective e
        WHERE e.source_run_id=? AND e.rule_version=? AND e.effective_eligible=1
          AND NOT EXISTS(
              SELECT 1 FROM http_checks h
              WHERE h.run_id=? AND h.url_clean=e.normalized_url
          )
        ORDER BY e.normalized_url
        """,
        (source_id(c, source_run), VERSION, excluded["run_id"]),
    ).fetchall()
    urls = [row["normalized_url"] for row in rows]
    invalid = [url for url in urls if validate_candidate(url)]
    if invalid:
        raise ValueError("Uložený opravený kandidát neprošel validací.")
    return urls


def approve_valid_manual_proposals(c: sqlite3.Connection, source_run: str,
                                   reviewed_by: str, reason: str) -> list[int]:
    """Schválí jen ruční návrhy s úspěšnou validací; rozhodnutí se nepřepisují."""
    ensure_schema(c)
    ids = [row[0] for row in c.execute("""
        SELECT correction_id FROM url_correction_effective
        WHERE source_run_id=? AND rule_version=?
          AND original_classification='invalid_url'
          AND repairability LIKE 'manual_%'
          AND proposed_url IS NOT NULL AND normalized_url IS NOT NULL
          AND validation_error IS NULL AND review_decision IS NULL
        ORDER BY correction_id
    """, (source_id(c, source_run), VERSION))]
    for correction_id in ids:
        c.execute("INSERT INTO url_correction_reviews(correction_id,decision,reviewed_at,reviewed_by,reason) "
                  "VALUES (?,'approved',?,?,?)",
                  (correction_id, utc_now(), reviewed_by, reason))
        c.commit()
    return ids


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("database/url_analysis.db"))
    parser.add_argument("--source-run", default="full_get_20260814")
    args = parser.parse_args()
    c = connect_database(args.database)
    result = prepare(c, args.source_run)
    output = Path("output")
    output.mkdir(exist_ok=True)
    (output / "correction_summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = c.execute("SELECT * FROM url_corrections WHERE source_run_id=? AND rule_version=? ORDER BY correction_id",
                     (source_id(c, args.source_run), VERSION)).fetchall()
    with (output / "url_corrections.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(rows[0].keys() if rows else [])
        writer.writerows(rows)
    effective = c.execute("SELECT * FROM url_correction_effective WHERE source_run_id=? AND rule_version=? ORDER BY correction_id",
                          (source_id(c, args.source_run), VERSION)).fetchall()
    with (output / "url_corrections_effective.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(effective[0].keys() if effective else [])
        writer.writerows(effective)
    reviews = c.execute("""SELECT r.* FROM url_correction_reviews r JOIN url_corrections k
        ON k.correction_id=r.correction_id WHERE k.source_run_id=? AND k.rule_version=? ORDER BY r.review_id""",
        (source_id(c, args.source_run), VERSION)).fetchall()
    with (output / "url_correction_reviews.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(reviews[0].keys() if reviews else [])
        writer.writerows(reviews)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    c.close()


if __name__ == "__main__":
    main()
