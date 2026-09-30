# dnswatch

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
