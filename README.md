# YARA EML Scanner

This project parses `.eml` files, extracts and decodes attachments, detects real file types from content, recursively unpacks supported containers, and scans the final files with YARA rules collected from:

- `Yara-Rules/rules`
- `Neo23x0/signature-base`

## Pipeline

1. Parse the `.eml` file with the Python email package.
2. Extract attachments and decode transfer encodings.
3. Detect the actual file type from magic bytes and archive signatures.
4. Recursively unpack container files into a temp workspace.
5. Compile YARA rules from the local third-party repositories.
6. Scan each extracted real file and emit structured results.
7. Log clean, malicious, skipped, and error states.

## Project Layout

- `src/yara_eml_scanner/cli.py` - CLI entrypoint.
- `src/yara_eml_scanner/pipeline.py` - End-to-end orchestration.
- `src/yara_eml_scanner/eml_parser.py` - EML parsing and attachment extraction.
- `src/yara_eml_scanner/file_types.py` - Content-based type detection.
- `src/yara_eml_scanner/container_unpacker.py` - Recursive unpacking.
- `src/yara_eml_scanner/rule_loader.py` - YARA rule discovery and compilation.
- `src/yara_eml_scanner/scanner.py` - YARA scanning and result shaping.
- `src/yara_eml_scanner/logging_utils.py` - Logging helpers.
- `src/yara_eml_scanner/models.py` - Shared dataclasses.

## Usage

```powershell
pip install -e .
python -m yara_eml_scanner.cli --eml .\sample.eml
```

Or use the console script:

```powershell
yara-eml-scan --eml .\sample.eml
```

## Output

The CLI prints a JSON report with:

- input EML path
- extracted files
- detected file types
- unpacking actions
- malicious / clean status
- triggered YARA rules
- compile and extraction errors

## Notes

- The scanner never trusts only the file extension; it inspects file content.
- Temporary files are created under a managed temp workspace and cleaned up automatically.
- Some third-party YARA rules may fail to compile; those files are skipped and reported without stopping the scan.
