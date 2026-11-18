# Patrick (PHP Advisory Lens)

Patrick is a local-first PHP security assessment tool with a CLI and optional
loopback-only Web UI. Each scan mode has a distinct name and scope so users can
tell whether a result came from
project declarations, PHP source call signatures, one PHP executable, or
host-local PHP inventory. A separate definitions mode refreshes the local
PHP-core advisory catalog. Patrick does not install or modify scanned projects.
Composer dependency scans submit exact package names and locked versions to
OSV unless `--offline` is selected; project paths, source, and lock-file
contents are not sent.

The bundled runtime catalog contains PHP-core advisories CVE-2026-109618 and
CVE-2026-109619. The definitions update can also add supported PHP extension
advisories to the user-local catalog. PHP.net release metadata supplies
current version, support, and security-release information; it is not a
complete CVE feed. Advisory thresholds remain curated and linked to upstream
references.

## Requirements

- Python 3.11 or later
- FastAPI and Uvicorn (installed automatically with the package)

## Scan modes

| Mode | Feature label | Scope |
| --- | --- | --- |
| `project` | **Project Version Declaration Scan** | Reads supported PHP version declarations in a project folder and assesses them against the curated runtime advisory catalog and PHP lifecycle data. Default mode. |
| `source` | **PHP Source Syntax Scan** | First checks the local PHP CLI environment, then lexically recognizes data-defined function-call signatures in PHP code, excluding comments and string contents. The environment check can be skipped explicitly. Findings are heuristic candidates, not proof of vulnerability or exploitability. |
| `environment` | **Local PHP Runtime Scan** | Inspects one explicitly selected PHP executable's version, loaded modules, and INI paths, then assesses PHP-core and matching loaded-extension advisories and reports PHP lifecycle status. |
| `web-runtime` | **Local PHP Web Runtime Scan** | Inspects explicitly selected local PHP-FPM and/or Apache/httpd executables. PHP-FPM is assessed for PHP-core and matching loaded-extension advisories and lifecycle status; Apache version and loaded modules are inventoried, but are not vulnerability-assessed in this release. |
| `device` | **Local Host PHP Inventory Scan** | Finds known PHP executable names in the local operating system's `PATH` and reports their paths without running them. Despite the mode name, it does not scan a separate device, remote host, or the full disk. |
| `dependencies` | **MySQL & Third-Party Dependency Scan** | Checks exact packages in `composer.lock` against OSV and optionally inspects an explicitly selected local MySQL server binary against locally cached NVD MySQL definitions. `--offline` skips OSV requests. |
| `definitions` | **PHP Vulnerability Definition Update** | Fetches PHP CNA records from NVD, validates supported PHP-core and named extension version thresholds, cross-checks linked PHP-src GitHub advisory thresholds, refreshes the local MySQL catalog, and selects the default PHP-version profile shown by the definition-list job. |
| `list-definitions` | **Vulnerability Definition List** | Lists supported PHP CVE definitions affecting the selected PHP major.minor branch, or all branches, ordered by publication date descending. The active branch profile is shown explicitly; MySQL definitions are listed only in all-branches view. |

These are separate operations and findings are not interchangeable. Project
declarations do not establish which binary runs in a live environment. A
source-call match does not establish a CVE. A CLI binary does not
establish the PHP-FPM or Apache runtime. Patrick is ready for **controlled
beta testing and local evaluation**, but is not a complete PHP antivirus or
vulnerability scanner and should not be treated as production security
assurance.

### Beta testing scope

Beta testers should evaluate installation in a fresh Python environment, the
CLI scan modes, the loopback-only Web UI, network-consent prompts, PHP-version
definition profiles, and how clearly incomplete or unsupported coverage is
reported. Please report reproducible bugs, confusing output, and environment
details needed to reproduce a result.

Treat all results as advisory. PHP core is the primary vulnerability coverage
target; extension coverage is lower-priority and best-effort, and Patrick does
not cover every extension or every vulnerability. An empty result, a
successful definition update, or a recent update timestamp does not prove that
a project or runtime is vulnerability-free. Source-call matches are heuristic
candidates, and a PHP-version profile only filters definitions Patrick
currently supports for that branch.

## Installation and usage

Run from the source tree:

```sh
PYTHONPATH=src python3 -m patrick --mode project /path/to/php-project
```

Or install locally:

```sh
python3 -m pip install .
patrick --mode project /path/to/php-project
```

For development and tests, install the optional test dependency:

```sh
python3 -m pip install -e '.[test]'
PYTHONPATH=src python3 -m unittest discover -s tests
```

### Parameters

| Parameter | Required | Meaning |
| --- | --- | --- |
| `target` | By mode | Existing project directory for `project`, `source`, and `dependencies`; not used by `environment`, `device`, or `list-definitions`. |
| `--mode project\|source\|environment\|web-runtime\|device\|definitions\|dependencies\|list-definitions` | No | Select a named feature; defaults to `project`. |
| `--rules PATH` | No | Runtime advisory JSON catalog; defaults to the updated user cache when present, otherwise the bundled catalog. In source mode, this is used for the environment preflight; in web-runtime mode it is used for PHP-FPM; in list-definitions mode it selects the PHP catalog to list. |
| `--source-rules PATH` | No | PHP source call-signature JSON catalog; valid only for `source`. |
| `--php-bin PATH` | For `environment` | Select the PHP executable to inspect. In `source` mode, overrides the default PHP executable found on `PATH`. |
| `--php-fpm-bin PATH` | For `web-runtime` | Explicit local PHP-FPM executable to inspect. Its version and module list are checked against the PHP runtime catalog. |
| `--apache-bin PATH` | For `web-runtime` | Explicit local Apache `httpd` executable. Patrick records its version and modules reported by `httpd -M`; Apache CVEs are not assessed yet. |
| `--format text\|json` | No | Human-readable (default) or machine-readable JSON output. |
| `--offline` | No | Skip live PHP.net, endoflife.date, and OSV requests. Cached lifecycle data may still be used; Composer advisory results are unknown without OSV responses. |
| `--mysql-bin PATH` | For `dependencies` | Select a local `mysqld`, `mysqld-debug`, or `mariadbd` executable. Patrick runs only `--version`; it does not start or connect to a server. MariaDB is reported separately and is not matched against Oracle MySQL advisories. |
| `--skip-environment-check` | No | In `source` mode, bypass the local PHP runtime preflight and scan source directly. |
| `--help` | No | Show options and exit. |

Examples:

```sh
# Inspect declarations in a project (checks PHP.net first).
patrick --mode project ./my-php-project

# Scan PHP source code with the bundled function-call signature catalog.
patrick --mode source ./my-php-project

# Select a PHP CLI binary for the source-mode environment preflight.
patrick --mode source ./my-php-project --php-bin /usr/bin/php

# Skip the environment preflight if it was already checked.
patrick --mode source ./my-php-project --skip-environment-check

# Inspect one PHP CLI executable.
patrick --mode environment --php-bin /usr/bin/php

# Inspect explicit local PHP-FPM and Apache executables.
patrick --mode web-runtime --php-fpm-bin /usr/sbin/php-fpm --apache-bin /usr/sbin/httpd

# Discover PHP executable candidates on the local host's PATH (does not run them).
patrick --mode device

# Generate JSON for CI.
patrick --mode project ./my-php-project --format json

# Scan without network access.
patrick --mode project ./my-php-project --offline

# Supply custom catalogs.
patrick --mode project ./my-php-project --rules ./security/php-runtime.json
patrick --mode source ./my-php-project --source-rules ./security/php-source.json

# Fetch and validate PHP vulnerability definitions, setting the PHP 8.2 list profile.
patrick --mode definitions --php-version 8.2

# List definitions affecting the selected PHP branch (PHP 8.2 in this example).
patrick --mode list-definitions

# Override the saved profile and list definitions for every PHP branch.
patrick --mode list-definitions --php-version all

# Check locked Composer packages against OSV and inspect a local MySQL server binary.
patrick --mode dependencies ./my-php-project --mysql-bin /usr/local/mysql/bin/mysqld

# Run dependency checks without contacting OSV (uncached package assessments are unknown).
patrick --mode dependencies ./my-php-project --offline

# Launch Patrick's local web interface at http://127.0.0.1:8000.
patrick-web

# Choose another local port if 8000 is already in use.
patrick-web --port 8765
```

### Local Web UI

The optional FastAPI interface exposes the same eight CLI jobs and calls the
existing CLI job logic directly. It binds only to `127.0.0.1`; there is no
option to expose it on a LAN or public interface. The default address is
`http://127.0.0.1:8000`; use `--port` to select a different local port. Stop
the server with Ctrl-C.

Select a job to reveal its required fields and optional settings. Project paths
are free-form and refer to files accessible to the account running Patrick.
Optional switches start unchecked. Live PHP release/lifecycle checks and OSV
lookups are disabled until selected; definition refresh requires an explicit
network opt-in. Before any network request, Patrick explains the purpose and
asks for confirmation. Permission defaults to the current web-server session.
“Always allow” saves permission separately for PHP release metadata, OSV
lookups, or definition refreshes. The UI shows saved permissions and provides
a control to revoke saved and current-session permissions. Saved choices are
stored in the user's configuration directory under
`patrick/web-ui-consent.json`.
The definitions update and list jobs let you choose a PHP major.minor branch
or `all`; the active profile and the core-first, best-effort extension scope
are shown beside the form.
The page files are maintained separately in `src/patrick/web/`
(`index.html`, `style.css`, and `app.js`) and are included in installed
packages. FastAPI serves these same-origin assets directly; no template engine
or additional web dependency is required.

Only one scan may run at a time. The page reports job progress/status and
displays the final CLI report as plain text in a terminal-style panel. It does
not execute project PHP or construct shell commands. Bind only to loopback;
the interface can inspect paths available to the local user and should not be
proxied or exposed to other machines.

Definitions mode downloads the NVD PHP CPE result set and selects records whose
CVE CNA is `security@php.net` and whose structured affected package is PHP core
or one unambiguous named PHP extension. Extension package names and exact PHP
release thresholds must be supported; unsupported or ambiguous ranges are
reported rather than guessed. When NVD links a PHP-src GitHub advisory, Patrick
also reads its patched-version section; a mismatch or ambiguous range is
reported and that record is not added or amended. Validated rules are written atomically to the
user cache at `$XDG_CACHE_HOME/patrick/php-runtime-updated.json` or
`~/.cache/patrick/php-runtime-updated.json`. Normal scans use this
cache automatically; `--rules` explicitly selects a different catalog.
The same explicit update also retrieves NVD records for Oracle MySQL and stores
safely modelled version ranges separately at
`$XDG_CACHE_HOME/patrick/mysql-advisories.json` or
`~/.cache/patrick/mysql-advisories.json`. Complex or ambiguous CPE
conditions are not applied. Dependency scans do not query NVD; they use this
local catalog. The selected MySQL binary's version is not sent to NVD.

This update mode is explicit rather than a hidden network request on every
scan. PHP advisories without a supported package identity or range remain
out-of-scope; their count is reported. The updater does not execute downloaded
data. PHP.net's release endpoint remains separate from CVE ingestion and is used by
project and runtime release checks. Normal scans report the cached
definition-update status;
an incomplete or invalid update is shown as a warning and yields exit code `3`
when no higher-priority finding already determines the result.

The updater maintains one shared PHP definition catalog containing all
supported branches, so selecting `--php-version 8.2` does not discard rules
for PHP 8.3, 8.4, or other branches. It saves PHP 8.2 as the default profile
for `list-definitions`. That profile lists rules whose validated affected
version data includes PHP 8.2, regardless of publication year; use
`--php-version all` to show all branches and the separate MySQL catalog. A
PHP branch profile prioritizes PHP core. Extension advisories are included
when their supported affected-version data matches the branch, but extension
coverage is best-effort and does not include every extension or vulnerability.
An empty or partial profile is not proof that the branch has no vulnerabilities.
The Web UI exposes the same profile selector and displays the selected
coverage next to the job form.

The `list-definitions` mode is offline and read-only. It lists the PHP catalog
that normal runtime scans use (updated user cache when present, otherwise the
bundled catalog), plus the available local MySQL catalog used by dependency
scans. A custom `--rules` path selects a different PHP catalog for this view;
it does not alter the MySQL catalog. Rows include the CVE ID, publication date,
component, severity, title, references, and catalog source. Rows with missing
or invalid publication dates are retained after dated rows and explicitly
marked. Catalog check timestamps and missing definition metadata are reported.
A missing or partial MySQL catalog is reported as incomplete. This is
a transparency view of Patrick's local definitions, not a complete CVE feed;
PHP source signatures and OSV dependency advisories are not included.

## Operation flow

### Project Version Declaration Scan

1. Validate the target directory and load the bundled or supplied runtime
   advisory catalog.
2. Check PHP.net release metadata for branches listed in that catalog, unless
   `--offline` was selected. Successful results are cached locally. On a
   failed request Patrick uses available cached data and reports warnings.
3. Walk the project, excluding common dependency and VCS directories, and read
   supported PHP version declarations.
4. Compare declarations with curated advisory thresholds and latest-release
   facts, keeping those results separate.
5. Print the feature-labeled report and return an exit code.

### PHP Source Syntax Scan

Unless `--skip-environment-check` is selected, first locate `php` on `PATH`
(or use the explicit `--php-bin` path), inspect its version, loaded modules,
and INI paths, and compare the observed runtime version with the runtime
advisory catalog and PHP.net release data. Patrick then scans bounded PHP
source files and reports configured call candidates by file, line, and column
even if the environment check is affected, unknown, or unavailable.
The report presents the environment result before the source findings. A
`no_known_issues` assessment means the observed PHP version passed the bundled
core rules, loaded-extension matching, and available release comparison; an
incomplete extension assessment is reported as unknown. It is not a general
guarantee that the host or project is secure, and exact extension builds and
distribution backports are not verified.

If PHP is not found on `PATH`, Patrick still performs the source scan and
reports the environment check as unavailable; choose `--php-bin` or explicitly
skip the check. `--offline` skips PHP.net and endoflife.date requests, not the
local PHP executable inspection or bundled runtime advisory comparisons;
cached lifecycle data is still used when available. The preflight describes
the local PHP CLI, not necessarily the PHP version used by the project, a
container, FPM, or Apache.

After preflight, this mode lexically distinguishes PHP code from inline HTML,
comments, and string or heredoc contents before matching configured function
calls. It accepts whitespace and qualified function names, and excludes
function declarations and object/static method calls for call-signature rules.
The scanner is not a full PHP parser: it does not validate program syntax,
analyze calls embedded in interpolated strings, execute project code, or
establish data flow. Findings remain heuristic candidates.

### PHP Lifecycle Status

Project declarations and inspected PHP runtimes are also compared with
endoflife.date's PHP cycle data. The report identifies active support,
security-maintenance, and end-of-life phases, with support/EOL dates, the
latest listed version and release date, and LTS status when available. Status
is derived from the support and EOL dates as of the check date. These lifecycle
facts are separate from PHP.net's latest-release/security-release comparison
and from CVE threshold findings. EOL reports that a branch no longer receives
upstream maintenance; it is not itself a CVE determination or a configured
minimum version. Patrick does not reject or skip scans for older PHP versions.

Lifecycle data is fetched from `https://endoflife.date/api/php.json` and cached
locally. A refresh failure can use cached data with a warning. `--offline`
skips the network request but still uses available cached lifecycle facts. An
unknown branch or missing cache is reported as unknown, never as supported.

### Local PHP Runtime Scan

Validate the selected executable and invoke it with `--version`, `-m`, and
`--ini`. Report its version, loaded modules, and INI paths; assess the observed
PHP version against runtime rules and PHP.net release data. PHP startup may
load configured extensions, but Patrick does not invoke application scripts.
This mode inspects one executable, normally CLI PHP. It matches loaded module
names to validated PHP extension advisories and compares the PHP runtime
release with their PHP release thresholds. A match below a fixed threshold is
a potential finding, not proof: Patrick does not independently observe the
extension's exact build or distribution backports. Extension coverage is
reported as partial when modules are loaded, and modules without matching
advisory definitions are listed as not assessed, not clean.
Project version declarations cannot identify which extensions are installed
or loaded.

### Local Host PHP Inventory Scan

Search the current host's `PATH` for known PHP executable names and report
their paths. This discovery mode deliberately does not execute candidates;
select one explicitly with Local PHP Runtime Scan to inspect its version and
configuration. It does not search the whole filesystem or connect to another
device.

### PHP Vulnerability Definition Update

Run `patrick --mode definitions` to refresh the default PHP-core
catalog. Patrick selects PHP CNA records from NVD's PHP CPE response, requires
exact semver fixed-version thresholds, and cross-checks any linked PHP-src
GitHub advisory before applying the record. Existing validated entries are
amended when the structured upstream data changes; records removed, withdrawn,
or reassigned upstream are retained but flagged for investigation. A record
with conflicting, missing, or unsupported version information is skipped and
reported; other valid records can still update the cache with an overall
`partial` status.
Review that status before relying on the refreshed catalog.

The updater covers supported PHP-core (`php-src`) and unambiguous named PHP
extension records. Incomplete NVD records, ambiguous packages, and unsupported
range expressions remain outside coverage. A successful update means the
selected source data was retrieved and validated, not that those sources
enumerate every PHP vulnerability.

## Output and exit codes

JSON output includes the feature name and mode, findings or runtime
observations, evidence, applicable update-check status, issues, and limitations.

- `0`: the selected mode completed without known affected results, source
  candidates, or unknowns.
- `1`: an advisory threshold is not met, a PHP.net security release is newer,
  or a declared/observed PHP branch is end-of-life;
  in source mode, at least one signature candidate was found or the checked
  local runtime is potentially affected.
- `2`: invalid input, rule catalog, or scan error.
- `3`: a result or update check is unknown, a warning occurred, or no
  applicable PHP files or executable was found.

## Project declaration coverage and limitations

Project mode reads:

- Dockerfiles and `FROM` instructions naming official `php` images.
- YAML `image:` declarations naming official `php` images.
- `.php-version` and PHP entries in `.tool-versions`.
- Exact PHP versions in `composer.json`'s `config.platform.php`.

These are declarations, not proof of the PHP process serving production
traffic. Project mode does not connect to servers or containers, run PHP,
inspect image contents, fetch CVE advisories, or scan PHP source. Tags pinned
to digests, build arguments, non-exact versions, unrecognized branches, and
unsupported declarations remain unknown.

Source mode checks the local PHP CLI before source scanning unless explicitly
skipped. A local environment result does not attest to the project’s deployed
runtime. Source scanning checks `.php`, `.phtml`, `.php3`, `.php4`, `.php5`,
and `.inc` files up to 1 MiB each, excluding common dependency,
virtual-environment, and VCS directories. It excludes comments, strings,
heredoc/nowdoc bodies, and inline HTML before matching configured signatures;
it remains lexical analysis rather than full parsing or data-flow analysis.

Environment mode executes the explicitly selected PHP binary with the
inspection arguments `--version`, `-m`, and `--ini`. PHP startup may load
configured extensions. It does not prove which runtime serves production
traffic or inspect a separate FPM pool or Apache worker.

Web-runtime mode requires at least one explicitly selected local executable.
For PHP-FPM it runs `-v` and `-m`, then assesses the observed PHP version
against the PHP runtime catalog and PHP.net release data. For Apache it runs
`-v` and `-M`; `-M` reads the selected installation's configuration and may
load configured modules, but does not start the server. Apache version and
module output are inventory only because Patrick does not yet include an Apache
advisory catalog. A failed component inspection or an Apache inventory-only
result is reported as incomplete, not clean. Neither component inspection
proves that the selected executable/configuration serves a project or matches
a running service. Use only trusted local executables and configurations.

No mode connects to a remote server or device. Device mode only finds known
PHP executable names in the current `PATH` and does not execute them.

The CLI checks PHP.net's official release JSON and endoflife.date's PHP
lifecycle API for project declarations and runtime preflights. Requests send no
project paths or source contents. PHP.net release facts and lifecycle facts
are cached separately under the application cache directory. `--offline`
disables live requests and reads cached lifecycle facts when available; without
a complete cache the report marks lifecycle status unknown.
Results are cached under `$XDG_CACHE_HOME/patrick/` or
`~/.cache/patrick/`. If PHP.net is unavailable, cached metadata is
used where possible and the failed check is reported rather than treated as
clean. `--offline` skips the request and reports release status as unknown.

PHP.net release metadata is authoritative for release versions, support status,
and security-release tags, but it does not enumerate every vulnerability.
Patrick does not automatically add vulnerability rules from release notices.
The bundled runtime catalog currently contains two PHP-core advisories:
CVE-2026-109618 and CVE-2026-109619. Review upstream advisories and link every
curated rule to its source. A clean result is not proof that a deployed system
is safe.

The optional Web UI reuses the CLI job logic and report output. It binds only
to loopback and should not be proxied or exposed to other machines.

## Runtime advisory catalog

The bundled catalog is `src/patrick/rules/php-runtime.json`. A custom
catalog is a UTF-8 JSON object with `schema_version: 1` and a non-empty `rules`
array:

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "CVE-YYYY-NNNNN",
      "title": "Example PHP runtime advisory",
      "severity": "high",
      "component": "php-core",
      "summary": "Short explanation of the affected PHP runtime.",
      "references": ["https://example.invalid/advisory"],
      "fixed_versions": {
        "8.4": "8.4.99"
      }
    }
  ]
}
```

`fixed_versions` maps a PHP `major.minor` branch to its first fixed release.
`component` identifies the affected product area (`php-core` or
`php-extension`). Extension rules also require `package_name`, which must match
the module name exposed by PHP. Extension rules are assessed only against
observed loaded modules, using the PHP release threshold as a proxy; exact
extension builds and downstream backports remain unknown. The scanner compares
exact three-part PHP versions only. Catalog data cannot load or execute custom
code. Review catalog changes against upstream advisories before use.

## Source-signature catalog

The bundled source catalog is `src/patrick/rules/php-source.json`.
It is separate from runtime CVE rules and has `schema_version: 1` with a
non-empty `rules` array. Each rule has a unique `id`, `title`, severity
(`critical`, `high`, `medium`, `low`, or `info`), `summary`, `pattern`, and
`references`; optional `case_sensitive` defaults to `false`. Patterns are
literal text, limited to 256 UTF-8 bytes; they are not regular expressions or
executable code. Function-call patterns such as `system(` are matched in PHP
code after comments, strings, heredoc/nowdoc bodies, and inline HTML are
excluded. Whitespace and qualified names are supported for these signatures.
Other literal patterns are searched only in PHP code. Matching is
case-insensitive by default and can be made case-sensitive with
`"case_sensitive": true`. The bundled signatures currently look for `eval(`,
`unserialize(`, `shell_exec(`, and `system(`. They flag potentially risky
constructs for review, not confirmed vulnerabilities; data flow and runtime
behavior are not analyzed.

## Development

For a clean local beta-test setup, create and activate a virtual environment,
install Patrick with its test dependency, then run the test suite:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
PYTHONPATH=src python -m unittest discover -s tests -v
```

On Windows PowerShell, activate the environment with
`.venv\Scripts\Activate.ps1`. To test the Web UI, run `patrick-web` from the
activated environment and open `http://127.0.0.1:8000`. Use `patrick-web
--port 8765` if the default port is unavailable. Test live definition updates
only when you intend to contact the documented external sources and confirm
the network request in the UI.

In Windows PowerShell, set the source path before running the test suite:

```sh
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```



## License

MIT. See [LICENSE](LICENSE).

## Project name

Originally called "PHP Security Scanner (PHPSS)" but then renamed it to "Patrick", and a descriptive working name “PHP Advisory Lens”. 