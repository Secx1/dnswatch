# Contributing

Issues and focused pull requests are welcome. Please:

- explain the detection or parser behavior being changed;
- add deterministic synthetic-log tests for new rules;
- do not add network access, live DNS lookups, or private log data;
- document new options and false-positive considerations.

Run the local checks before submitting:

```console
python -m unittest discover -s tests -v
```
