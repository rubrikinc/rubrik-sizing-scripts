# The run log

How the log in the zip is produced, what is in it, and how to add a fix for a new error. For what the log looks like to a
user, see `user-guide.md`; for what to do about an error, `troubleshooting.md`.

## What the log is

A transcript of the screen. It holds what a person watching the run saw, in the same order, as plain text, plus a header and
a closing summary. It is not a debug log:

| In the log | Not in the log |
|------------|----------------|
| everything printed to the console (banner, tables, `✓` lines, questions and your answers) | spinners and other redraws |
| the log records the screen shows (AWS: INFO and above; Azure and GCP: WARNING and above) | DEBUG records, and library records below WARNING |
| the header and the run summary | colour codes |

`--verbose` changes only the screen. The log is the same with or without it.

The log is streamed while the run goes: every line is written and flushed as it happens, into the folder the results go to
(the `--output` folder; for a multi-account AWS scan without `--output`, the current folder, where the zip goes), named
`output_<cloud>_<timestamp>.log`. GCP starts it in a temp file and moves it into the output folder as soon as the config
has said where that is. When the run finishes the log is added to the zip under the same name and the loose file is
removed. With `--anonymize` the zip holds a note instead, and the real log is written beside the zip as
`output_<cloud>_not_anonymized_<timestamp>.log`. The final lines that name the zip are printed after the log has been
sealed into it, so they are on the screen but not in the file.

## How a run ends

A run that does not finish leaves its log in the output folder, written up to that moment, and every way a run can end
writes one last line, `Run ended: ...`, so a log either says how its run ended or is visibly cut off:

| How the run ends | The last lines of the log | Exit code | Results |
|------------------|---------------------------|-----------|---------|
| it finishes | `Run ended: scan finished at HH:MM:SS`, after the run summary; the log goes into the zip | 0 | the zip |
| an error | `Run ended: failed with <Error>: <message>`, that the zip was not written, and the traceback | non-zero | none |
| it exits with an error code | `Run ended: exited with code N` and that the zip was not written | N | none |
| Ctrl-C, `kill`, or the terminal closing | `Run ended: stopped by Ctrl-C (SIGINT)`, `SIGTERM` or `the terminal closing (SIGHUP)`, and that the zip was not written | 130, 143, 129 | none |
| `kill -9`, a power cut | nothing: no process gets to write after that. The log stops mid-run with no `Run ended` line | | none |

A log with no `Run ended` line was cut off. AWS adds where finished accounts are kept, because a multi-account scan can be
resumed. Three cases leave nothing behind, because the message is already on the screen in full: a sign-in problem and a
bad option (AWS), and `--dry-run` (GCP). The partial log is the real log, not anonymized, whatever `--anonymize` says.

The handlers for Ctrl-C, `SIGTERM` and `SIGHUP` write the last line, force it to disk and exit at once with `os._exit`,
not `sys.exit`, because `sys.exit` waits for the scan's worker threads, which can be minutes. They are installed in the main
thread once the log is open, and replace the default, which for `SIGTERM` and `SIGHUP` is to die without a word.

## The pieces

| Piece | Where | What it does |
|-------|-------|--------------|
| `common/runlog.py` | the original | the transcript writer, the end-of-run line and the signal handlers, the issue registry, the fixes lookup, the digest; standard library only |
| `<tool>/runlog_core.py` | a byte-identical copy in each tool | an installed tool cannot import `common`, so it carries a copy; a test fails if a copy differs |
| `<tool>/runlog.py` | each tool | that cloud's fixes (`SOLUTIONS`), the masks that merge names (`MASKS`), the header, and for Azure and GCP the console that logs itself |
| `<tool>/logging_setup.py` | each tool | `add_log_file()` attaches the transcript handler to the root logger |

`TranscriptHandler` writes the records the screen shows. It takes the level name from the record's number, because the AWS
console formatter rewrites `record.levelname` with colour codes. Library records (`botocore`, `urllib3`, `azure.*`,
`google*`, and so on) are kept only at WARNING and above.

`LoggedConsole` (Azure and GCP) is a rich console whose `print` also writes the plain-text rendering to the transcript. A
print that renders nothing, which is how a spinner redraws, is skipped. AWS prints its boxes through `runlog.say()`.

## Header and summary

The header (`# Run log: ...`) gives the tool, the commit it ran from (hash and date), the versions of the main packages, the
Python and platform, and the command line. The summary at the end is `core.digest_lines()`: every warning and error of the
run, grouped, each with its count, one example and its fix.

For all three tools the screen, and so the log, also holds the totals block (`totals.py`) just before the run summary. It
is computed from `csv_export.rows_by_file()`, the rows the CSV files are built from, so it cannot disagree with them, and
it holds only counts and sizes. A failure inside it is a warning and never stops packaging.

## How problems are grouped

Every WARNING and ERROR record is added to a registry. Two messages are the same problem when they are equal after the parts
that vary are masked: GUIDs, ISO times, numbers of five or more digits, and whatever the tool's `MASKS` name (AWS: regions
and ARNs; Azure: resource paths; GCP: project IDs). So a failure repeated for 249 storage accounts is one problem with a
count of 249. Problems are listed with errors first, then by count.

A tool can also name the **cause** of a message with `core.configure(..., cause=fn, noun="project")`. The function
`fn(message)` returns `(key, scope)`, and messages with the same key are one problem however they are worded. The scopes
are collected so the entry says where it happened: `3 projects:` and a `Projects:` line. GCP does this, because the access
check and the collector word one failure differently and it happens on each project. Its key is the fix, the service the
message is about (read from its label, with the project name removed) and, for an API that is off, the project Google
charges, since enabling it elsewhere does not help. A message with no known fix, or a hook that raises, falls back to the
masked text. AWS and Azure set no hook.

A blocked pre-flight check is added to the same registry by `problem_block()`, so it appears in the summary with its fix,
once per project it was blocked in.

GCP also drops the Google API client's own warning for a 4xx answer (`Encountered 403 Forbidden ...`): it names no project or
service, and the collector that made the call reports the same failure with both. A 429 is kept.

## A fix

A fix is a `Solution(id, pattern, fix)`. The first solution whose `pattern` matches the text `service | code | message`
wins, so order matters: put the specific ones first (an organization-policy denial before a plain access denial). `fix` may
use the pattern's named groups, for example `{project}` and `{service}`.

The text of a fix is laid out by `fix_lines()`: sentences are wrapped under `Fix:`, and a line starting `Run: ` is a command
that is printed on a line of its own and never wrapped, so it can be copied. The last line is the link to the
troubleshooting section named by the id.

To add or change one:

1. Add the `Solution` to the tool's `runlog.py`. The id starts with the tool (`aws-`, `az-`, `gcp-`) and is unique.
2. Add a section to `troubleshooting.md` with `<a id="the-id"></a>` above its heading, and a row in the index.
3. Add the real error message to `REAL_MESSAGES` in the tool's `tests/test_runlog.py`.

The tool's `tests/test_docs.py` fails if a fix has no section on the troubleshooting page, so step 2 cannot be forgotten.

## What may be logged

The cloud's own message is kept for the screen and the log: it is what diagnoses a problem. The pre-flight table and CSV
carry only the short error code, because the CSV is shared and a message can name accounts and resources that the
anonymizer cannot label inside text. Library DEBUG output, which can carry request details, is not written at all.

## Testing

- A transcript test reads the log back out of the zip of a real `main()` run, not just from a handler.
- The end-of-run tests send real signals (`SIGTERM`, `SIGHUP`, `SIGINT`, `SIGKILL`) to a child process that runs the tool's
  `main()`, and read the partial log it leaves. A handler that is never triggered proves nothing.
- Compare `record.levelno`, never `levelname`: the console formatter rewrites the latter.
- Import the collectors at the top of a test module, so a patch cannot be bound into them at first import.
- The digest is global: reset `ISSUES` between tests.
