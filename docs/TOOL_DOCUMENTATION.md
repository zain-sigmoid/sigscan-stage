# Sigscan Code Review Tool

Comprehensive static analysis suite that combines security, privacy, quality, performance, and compliance checks behind a single Streamlit interface. This document explains how the tool is structured, how to run it, which analyzers are available, and what to expect in the outputs.

## Architecture at a Glance
- **UI layer:** `main_consolidated.py` (Streamlit) handles uploads, analyzer selection, progress, and rendering of findings/metrics.
- **Extraction and filtering:** `utils/prod_shift.Extract` safely unpacks uploaded ZIPs, prunes noisy folders (see `docs/FILE_FILTERING.md`), and resolves the project root. Single-file uploads are also supported.
- **Execution engine:** `core.engine.UnifiedAnalysisEngine` orchestrates analyzers (parallel or sequential), applies severity/confidence limits, and collects `AnalysisMetrics`.
- **Aggregation:** `core.aggregator.ResultAggregator` deduplicates similar issues, merges context, scores risk, and builds the `ConsolidatedReport` summary.
- **Models and contracts:** `core.models` defines shared types such as `UnifiedFinding`, `AnalysisConfiguration`, and `ConsolidatedReport`; `core.interfaces` defines analyzer contracts and the registry.
- **Logging:** `utils.logs_service` provides structured logging for the UI and analyzers.

## Getting Started
1. Clone and install:
   ```bash
   git clone https://github.com/zain-sigmoid/gstool.git
   cd gstool
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env  # populate values if needed
   ```
2. Launch the UI:
   ```bash
   streamlit run main_consolidated.py
   ```
3. Optional CLI workflow: generate `out.json` using the sigscan CLI (see README) and load it via the UI "Upload your output JSON file" flow.

### External Tooling
Several analyzers call external binaries when available. To get complete coverage, ensure these are on your `PATH`:
- Secrets: `gitleaks` (auto-fetched to `/tmp` on Linux via `ensure_gitleaks`, macOS users can `brew install gitleaks`).
- Compliance: `scancode` for license detection; `semgrep` for privacy rules.
- Maintainability and robustness: `radon`, `jscpd`, `bandit`, `mypy`, `semgrep`, `pylint`.

Missing tools downgrade only the affected analyzer; the rest of the suite continues to run.

## Using the Streamlit App
1. Choose an input:
   - **Project ZIP:** Upload a ZIP; it is unpacked into `user_project/` and sanitized to remove hidden/metadata entries.
   - **Single file:** Upload a lone `.py` file.
2. Select analyzers (all are selected by default).
3. Configure options:
   - Parallel execution toggle.
   - Include low-confidence findings.
   - Timeout and per-analyzer finding cap.
4. Run the analysis and watch progress. Results render across:
   - All findings list with severity/category filters.
   - Metrics and executive summary.
   - Export tab for saving reports.
5. Load past results from the history list or by uploading a previously generated JSON report.

## Analyzer Catalog

| Analyzer (module) | Focus | Key checks | External tools |
| --- | --- | --- | --- |
| Hardcoded Secrets (`analyzers/secrets_analyzer.py`) | Secrets and credentials | Gitleaks scan for hardcoded tokens/keys; entropy-based detection | `gitleaks` |
| Robustness (`analyzers/robustness_analyzer.py`) | Safety and error handling | Bandit security patterns, MyPy type errors, Semgrep rules, unsafe dict access heuristics | `bandit`, `mypy`, `semgrep` |
| PII/PHI (`analyzers/pii_analyzer.py`) | Privacy compliance | Regex/AST checks for emails, phone numbers, SSN, credit cards, Aadhaar/PAN, PHI logging, and sensitive variable names | None (patterns only) |
| Injection (`analyzers/injection_analyzer.py`) | Injection vectors | SQL/XSS/command/path/LDAP/code/XPath injection patterns; CWE mapping | None (patterns only) |
| Testability (`analyzers/testability_analyzer.py`) | Tests and coverage | Detects test files/fixtures, maps functions to tests, flags untested or poorly named tests | None (AST/regex) |
| Observability (`analyzers/observability_analyzer.py`) | Logging and monitoring | Logging coverage per function, error handling instrumentation, structured logging hints | None (AST/regex) |
| Readability (`analyzers/readability_analyzer.py`) | Style and clarity | Pylint score aggregation, naming/docstring/formatting checks, clustering of repeated issues | `pylint` |
| Maintainability (`analyzers/maintainability_analyzer.py`) | Complexity and duplication | Radon complexity/maintainability index, jscpd clone detection, per-function recommendations | `radon`, `jscpd` |
| Performance (`analyzers/performance_analyzer.py`) | Inefficient patterns | Nested loops, naive sorting, missing memoization, inefficient data structures, heavy regex | None (AST/regex) |
| Compliance (`analyzers/compliance_analyzer.py`) | Licensing and privacy | ScanCode license detection/clues, Semgrep privacy rules (GDPR/CCPA/HIPAA), clubbed findings | `scancode`, `semgrep` |

All analyzers emit standardized `UnifiedFinding` objects with severity, category, location, remediation guidance, and optional code snippets.

## What Happens During a Run
1. **Target discovery:** `core.file_utils.find_python_files` enumerates Python sources while skipping virtualenvs and cache directories.
2. **Analyzer execution:** `UnifiedAnalysisEngine` runs enabled analyzers (async, parallel by default) with the provided `AnalysisConfiguration`.
3. **Filtering:** Severity thresholds, confidence gating, and per-analyzer finding caps are applied.
4. **Aggregation:** Deduplication and cross-referencing reduce noise; summaries capture severities, category breakdowns, and top files.
5. **Presentation:** Streamlit UI renders findings with filtering by severity, category, type, or file. Code snippets and remediation text are shown when present.

## Output and Data Model
- Primary output is a `ConsolidatedReport` (see `core/models.py`) containing:
  - `findings`: List of `UnifiedFinding` entries with IDs, titles, descriptions, location (`file_path:line`), severity, category, code snippets, remediation, and tags.
  - `analysis_metrics`: Per-analyzer timing, file counts, and success/error flags.
  - `summary`: Risk score, severity/category breakdown, top problematic files, remediation complexity counts.
  - `analysis_config`: Snapshot of the configuration used for the run.
- Reports can be exported/imported as JSON for later viewing in the UI.

## Troubleshooting
- If an analyzer shows zero findings unexpectedly, confirm its external dependency is installed and reachable in `PATH`.
- ScanCode runs can take time on large trees; consider narrowing the upload to relevant code only.
- For long-running analyses, raise the timeout slider or disable parallelism when system resources are constrained.
- Logs are written via `utils.logs_service.logger`; check the Streamlit console for stack traces during development.

## Extending the Tool
- Implement a new analyzer by subclassing the appropriate base in `core/interfaces.py`, then register it in `main_consolidated.py` (or via the registry).
- Reuse `core.tool_runner.ToolRunner` when invoking external binaries to benefit from timeout handling and availability checks.
- Add new file filters in `core/file_utils` or `docs/FILE_FILTERING.md` if your projects contain custom build artifacts.

