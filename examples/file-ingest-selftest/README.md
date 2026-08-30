# File-ingestion self-test fixture

**Synthetic. Not a client export, and not a real scan of anything.**

`file-scan.yml` had never completed a run — it takes uploaded third-party scan
exports, and with nothing committed to point it at there was no way to exercise
the path end to end. Dispatching it against any directory in the repo failed with
`no input files`, which is correct fail-closed behaviour and also meant the
workflow could never be green.

These files exist so the ingestion path can be proven without a real export. The
hosts and findings are invented; `app.selftest.invalid` and `10.255.255.1` are in
reserved ranges precisely so nothing here can be mistaken for, or resolve to, a
real target.

Run it under a self-test client, never a real one:

    gh workflow run file-scan.yml -R IronCityIT/threat-inspector --ref main \
      -f files_path=examples/file-ingest-selftest \
      -f client_name=fixture-selftest \
      -f group=ingest

Using a real `client_name` would write invented findings into that client's
Firestore partition, which is the one thing this fixture must never be used for.
