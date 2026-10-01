# dnswatch

[![Release](https://img.shields.io/github/v/release/Secx1/dnswatch?display_name=tag)](https://github.com/Secx1/dnswatch/releases)
[![License](https://img.shields.io/github/license/Secx1/dnswatch)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Secx1/dnswatch?style=flat)](https://github.com/Secx1/dnswatch/stargazers)

`dnswatch` is an offline, read-only analyzer for Zeek `dns.log` TSV files. It
looks for explainable signals that are useful during triage:

- unusually long or high-entropy labels;
- repeated queries that may indicate beaconing or a misconfiguration;
- high NXDOMAIN rates by client;
- a small, configurable list of TLDs that deserve review.

The tool does not send packets, resolve domains, exploit services, or claim to
detect malware. Heuristics can produce false positives and should be reviewed
by an authorized analyst. Input is bounded to 5 MiB by default, and malformed
rows are skipped rather than executed.

**Research track:** threat intelligence / malware-analysis triage and incident
response analytics. It produces explainable weak signals for an authorized
analyst; it does not claim to identify malware or reconstruct an incident alone.

## At a glance

| Concern | Behavior |
| --- | --- |
| Input | Zeek `dns.log` TSV, including synthetic fixtures for repeatable tests |
| Network | None; the analyzer never resolves domains or sends packets |
| Output | Table for triage, JSON for pipelines, or SARIF for finding ingestion |
| Safety | Read-only parsing with a 5 MiB default input bound and skipped malformed rows |

## Review workflow

1. Export the relevant Zeek DNS log from an authorized environment and retain
   its collection window and sensor context.
2. Run the analyzer with the default thresholds, then review the raw rows behind
   each signal (long labels, entropy, repetition, NXDOMAIN rate, or TLD list).
3. Correlate weak signals with approved telemetry such as endpoint, proxy, or
   identity logs; a signal alone is not an incident conclusion.
4. Record the decision and any threshold changes, then rerun against a bounded
   fixture before promoting a detection rule.

## Usage

```bash
python -m dnswatch.cli examples/dns.log --format table
python -m dnswatch.cli examples/dns.log --format sarif --fail-on medium > results.sarif
```

Output formats are table, JSON, and SARIF. The test suite uses synthetic logs
and does not access the network.

## Development

```bash
python -m unittest discover -s tests -v
```

Use this project only with logs and systems you are authorized to analyze.

## License

MIT
