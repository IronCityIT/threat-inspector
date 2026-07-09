# ICIT Module Framework

Shared modular core for every ICIT scanning tool (Threat Inspector, ShadowScan,
Surge, Dynamic Experience Analyzer). Adopt this in each tool so a module looks
identical everywhere. Verified working: CIDR expansion, URL/domain/hostname parsing,
dedupe, module + group selection, JSON output, clean CLI errors.

## Files
- `targets.py`   — parse/normalize/validate targets (IP, CIDR, URL, domain, hostname, files)
- `base.py`      — `ScanModule` + `FileModule` interfaces + `Finding` dataclass (the contract)
- `registry.py`  — discover modules of either type, resolve `--modules` / `--group`, build catalog
- `cli.py`       — active-scan entry point (`run(target, ctx)`); emits the JSON contract
- `ingest.py`    — file-ingestion entry point (`ingest(file, ctx)`); emits the SAME JSON contract
- `modules/`     — one file per ACTIVE capability (ScanModule)
- `file_modules/`— one file per FILE format (FileModule), each wrapping an existing parser

## Two module types (both first-class)
A capability is one of two shapes. Never bend one into the other.

| Type         | Contract                | Input          | Entry point | Package        |
|--------------|-------------------------|----------------|-------------|----------------|
| `ScanModule` | `run(target, ctx)`      | live target    | `cli.py`    | `modules/`     |
| `FileModule` | `ingest(file, ctx)`     | uploaded file  | `ingest.py` | `file_modules/`|

Both return `list[Finding]` and flow through the identical analyze/store pipeline —
there is exactly one findings-JSON path and one AI flow. A `FileModule` declares
`extensions` (instead of `target_kinds`) and re-houses an existing parser; it does
not reimplement parsing. When several file modules accept the same extension
(e.g. `.csv`), `ingest.py` uses content auto-detection to route each file to one.

## Run it
```
# active scanners (live targets)
python3 cli.py --list-modules
python3 cli.py --group deep --targets "10.0.0.0/24,https://app.acme.com,acme.com"
python3 cli.py --modules port_scan,tls_check --targets-file scope.txt --client acme --scan-id 2026-07-08-01

# file ingestion (uploaded scan exports)
python3 ingest.py --list-modules
python3 ingest.py --group ingest --files scan1.xml,scan2.csv --client acme --scan-id 2026-07-09-01
python3 ingest.py --modules qualys_ingest --files-dir uploads/
```

## How to adopt it in a tool (the actual job)
1. **Read the existing Claude-generated Python first.** Inventory every capability it
   already performs. Do not delete logic — you are re-housing it, not rewriting from zero.
2. **Split the monolith.** Each distinct capability becomes one `ScanModule` subclass in
   `modules/`. Set `name`, `description` (white-labeled — no tool names), `target_kinds`,
   and `groups`. Move the existing scan logic into `run()`; return `Finding`s.
3. **Assign groups.** Tag each module `quick`, `standard`, and/or `deep` (a module can be
   in several). `quick` = fast/safe/passive, `deep` = full/intrusive/slow.
4. **Keep the shared core generic.** Don't fork `targets.py`/`base.py`/`registry.py` per
   tool — copy them as-is. Tool-specific behavior lives only in `modules/`.
5. **The dashboard reads the same catalog.** `registry.catalog()` is what renders the
   module checkboxes and group presets, plus the target input box. Selection in the UI
   maps 1:1 to `--modules` / `--group`. No second source of truth.

## Output contract (do not change shape)
```json
{ "client": "...", "scan_id": "...", "modules_run": ["..."],
  "target_count": 0, "findings": [ { "module","target","severity","title","detail","evidence" } ] }
```
This JSON is what flows to `consensus-engine` (via workflow_call) and then to the
`storeScanResults` Cloud Function. Same for every tool.

## Severity
`info | low | medium | high | critical` — enforced in `Finding`. Bad value = hard error.
