from __future__ import annotations

import csv
import io
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping


SEVERITIES = ("low", "medium", "high")
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    query: str = ""
    client: str = ""
    line: int = 0
    evidence: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        if value["evidence"] is None:
            value.pop("evidence")
        return value


def _decode_zeek_separator(value: str) -> str:
    if value == r"\x09":
        return "\t"
    return value.encode("utf-8").decode("unicode_escape")


def parse_zeek(text: str) -> Iterator[tuple[int, dict[str, str]]]:
    """Yield ``(line_number, record)`` from a Zeek TSV log.

    The parser is deliberately limited to text input and never executes or
    resolves values from the log. It accepts the standard ``#fields`` header.
    """
    separator = "\t"
    fields: list[str] | None = None
    for line_number, raw in enumerate(io.StringIO(text), start=1):
        line = raw.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#separator "):
            separator = _decode_zeek_separator(line.split(" ", 1)[1])
            continue
        if line.startswith("#fields"):
            payload = line[len("#fields"):].lstrip(" \t")
            fields = payload.split(separator)
            continue
        if line.startswith("#"):
            continue
        if fields is None:
            raise ValueError("Zeek log is missing a #fields header")
        row = next(csv.reader([line], delimiter=separator))
        if len(row) != len(fields):
            continue
        yield line_number, dict(zip(fields, row))


def read_zeek(path: str | Path, max_bytes: int = 5_000_000) -> Iterator[tuple[int, dict[str, str]]]:
    file_path = Path(path)
    if file_path.stat().st_size > max_bytes:
        raise ValueError(f"input exceeds the {max_bytes} byte safety limit")
    return parse_zeek(file_path.read_text(encoding="utf-8", errors="replace"))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _normalized_query(record: Mapping[str, str]) -> str:
    return record.get("query", "").strip().lower().rstrip(".")


def analyze(
    records: Iterable[tuple[int, Mapping[str, str]]],
    *,
    max_queries: int = 20,
    entropy_threshold: float = 3.5,
    max_query_length: int = 80,
) -> list[Finding]:
    findings: list[Finding] = []
    query_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    nxdomain_counts: Counter[str] = Counter()
    first_line: dict[str, int] = {}
    emitted_frequency: set[str] = set()
    emitted_nxdomain: set[str] = set()

    for line, record in records:
        query = _normalized_query(record)
        client = record.get("id.orig_h", "")
        if not query:
            continue
        query_counts[query] += 1
        first_line.setdefault(query, line)
        if client:
            client_counts[client] += 1
        if record.get("rcode", "").upper() in {"NXDOMAIN", "3"}:
            nxdomain_counts[client or "unknown"] += 1

        labels = query.split(".")
        longest_label = max(labels, key=len)
        if len(query) >= max_query_length:
            findings.append(Finding(
                "DNS-LONG-QUERY", "medium",
                f"query is unusually long ({len(query)} characters)", query, client, line,
                {"length": len(query), "limit": max_query_length},
            ))
        if len(longest_label) >= 16 and shannon_entropy(longest_label) >= entropy_threshold:
            findings.append(Finding(
                "DNS-HIGH-ENTROPY", "medium",
                "label has high character entropy; review for generated or encoded data",
                query, client, line,
                {"label_length": len(longest_label), "entropy": round(shannon_entropy(longest_label), 3)},
            ))
        tld = labels[-1] if labels else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding(
                "DNS-UNUSUAL-TLD", "low",
                f"query uses a TLD often seen in disposable or abuse reports (.{tld})",
                query, client, line,
            ))

    for query, count in query_counts.items():
        if count > max_queries and query not in emitted_frequency:
            findings.append(Finding(
                "DNS-HIGH-FREQUENCY", "low",
                f"query repeated {count} times; review beaconing or misconfiguration",
                query, "", first_line[query], {"count": count, "limit": max_queries},
            ))
            emitted_frequency.add(query)

    for client, total in client_counts.items():
        nx = nxdomain_counts[client]
        if total >= 5 and nx / total >= 0.5 and client not in emitted_nxdomain:
            findings.append(Finding(
                "DNS-NXDOMAIN-RATE", "medium",
                f"client returned NXDOMAIN for {nx} of {total} queries",
                "", client, 0, {"nxdomain": nx, "queries": total},
            ))
            emitted_nxdomain.add(client)
    return findings


def findings_as_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True)


def findings_as_sarif(findings: Iterable[Finding]) -> str:
    results = []
    rules: dict[str, dict[str, str]] = {}
    for finding in findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "shortDescription": {"text": finding.rule_id}})
        result = {
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity == "high" else "warning" if finding.severity == "medium" else "note",
            "message": {"text": finding.message},
        }
        if finding.line:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "dns.log"}, "region": {"startLine": finding.line}}}]
        results.append(result)
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "dnswatch", "rules": list(rules.values())}}, "results": results}]}, indent=2)


def findings_as_table(findings: Iterable[Finding]) -> str:
    rows = list(findings)
    if not rows:
        return "No heuristic findings."
    lines = ["SEVERITY  RULE                 QUERY / CLIENT                         MESSAGE"]
    lines.append("-" * 96)
    for finding in rows:
        subject = finding.query or finding.client or "(aggregate)"
        lines.append(f"{finding.severity.upper():8}  {finding.rule_id:20} {subject[:36]:36} {finding.message}")
    return "\n".join(lines)
