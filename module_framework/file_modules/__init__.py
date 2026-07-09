"""
file_modules — passive scan-export ingestion, one FileModule per format.

Each module here RE-HOUSES an existing threat_inspector parser (it does not
reimplement parsing): it wraps the parser, runs it over an uploaded file, and
converts the parser's ParsedVulnerability rows into framework Findings via
`_convert.to_findings`. Selection ("ingest only Qualys exports") therefore maps
1:1 to a parser, exactly like the active scanners map 1:1 to a probe.

Adopting the framework requires `module_framework/` on sys.path (flat imports:
`base`, `registry`) AND the tool package importable (`threat_inspector.parsers`).
The ingest CLI wires both; tests do the same.
"""
