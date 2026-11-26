# Changelog

## 0.2.0 (26 November 2026)

### Breaking changes
- `PIIAirgap.rehydrate()` needs an allow-list and validates types and keys. `allow` is now a
  required keyword argument of placeholder strings (`None`, strings, `bytes`, `bytearray` or
  non-string items raise `TypeError`). Unsupported payload types (`bytes`, `set`) raise
  `TypeError`, and restoring dict keys so that two become identical raises `ValueError`.
- `llm-pii-airgap rehydrate` needs `--allow-from SENT_PROMPT` or an explicit `--allow-all`.
- `scrub` now refuses non-UTF-8 and UTF-16 input with exit code 2 instead of replacing bad
  bytes with `U+FFFD`.
- Profiles whose `phone` field contains no ASCII decimal digits (`Nd`) are refused at load.
- Python 3.11 or newer is required. Python 3.13 and 3.14 are supported.

### Features
- `--version` prints the installed version.
- `check`, and the re-check `sanitize` runs before writing, also scan the text with invisible
  characters (all Unicode `Cf` format characters, variation selectors and blank fillers)
  removed and NFKC normalisation applied, and decode up to four levels of JSON inside JSON
  strings. `sanitize` refuses to write such text and says why.
- The `scrub` summary always lists every counter (`lines_read`, `rows_kept`,
  `duplicates_skipped`, `invalid_json`, `non_user_skipped`), zero or not.

### Hardening
- Scrubbing (`redact_secrets`) and harness-tag stripping run in linear time, including across
  thousands of distinct `<pasted_content_...>` and `<ide_...>` tag names. `<EMAIL>`,
  `<LONG_TOKEN>`, `<URL_WITH_CREDS>`, `<PRIVATE_KEY>` and the block and marker stripping
  used to slow down sharply on crafted input (a 200 KB string could take minutes). The
  `<PRIVATE_KEY>` search now stops at the last `END` line, which leaves its results as they
  were.
- Input containing NUL characters is refused across every command. This catches UTF-16 text
  without a byte order mark, which reads as valid UTF-8 and would otherwise pass `check` as
  clean.
- Output files for `sanitize`, `rehydrate` and `scrub` are written via a temporary file in
  the same folder and atomically renamed on success, so an exit-2 failure never truncates an
  existing target or leaves a partial file.
- Argument errors no longer repeat what was typed (a stray word of unquoted `-t` text, an
  unknown command, a value given to a flag).
- Encoding errors, oversized integers in `scrub` (`invalid_json`) and deeply nested JSON
  give a fixed message or skip the bad line instead of quoting input or printing a traceback.
- Output printed to the terminal is always UTF-8, so a legacy console code page no longer
  stops `rehydrate` from printing a name.

### Fixed
- `<API_KEY>` and `<DISCORD_TOKEN>` match tokens ending in `-`.
- `<URL_WITH_CREDS>` matches upper-case schemes such as `HTTPS://`.
- `<IP>` validates `0`–`255` octets and `<EMAIL>` skips `@version` package pins.
- `<PHONE>` and profile phone matching handle brackets and numbers preceded by `+` (such as
  unified diff lines), while `<PHONE>` ignores `+YYYY-MM-DD` dates.
- `<SECRET>` handles YAML block scalars (`|`, `>-`), `Authorization:` schemes (`Token`,
  `ApiKey`, …), `os.getenv` / `os.environ.get` defaults, chained assignments, `r"..."` and
  backtick strings with spaces, YAML `''` escapes, multi-line quoted strings, `--flag`
  quoted values, dotted key names, long key suffixes, values starting with `true`/`false`/
  `null`/`none` plus punctuation, unquoted values continued onto the next line with a
  trailing backslash, and redacts to end of line when a quote is unclosed.
- `<SECRET>` leaves uppercase `TOKENIZER` / `SECRETARY`, `token_type`, `PASS_RATE`, and
  `token: str = None` alone.
- Whole-token profile matching treats Unicode combining marks as part of a word so
  decomposed accents cannot split or extend a match across word boundaries.
- Harness-tag stripping preserves self-closing tags and Markdown `[Image ...](...)` links,
  keeps stripping valid blocks after a malformed unclosed tag, and checks drop prefixes after
  stripping harness tags.
- A profile value saved with a decomposed accent or full-width characters also matches its
  ordinary (NFC and NFKC) form.
- A profile, input file, `--allow-from` file or transcript saved with a UTF-8 byte order
  mark is read correctly instead of being refused or keeping the mark.
- A transcript text part whose `text` isn't a string is skipped instead of stopping `scrub`
  with a traceback, and a line nested too deeply for Python to read (Python 3.14 reads
  deeper nesting than earlier versions) or holding a `>4300`-digit integer counts as
  `invalid_json`.
- The help text of `--keep-tool-results` says what it does: it keeps the typed text of user
  records that also carry tool results, never the tool output.

### Packaging, documentation and tests
- The licence is declared in the SPDX form (`license = "MIT"`) that current setuptools
  expects. CI runs on Linux, macOS and Windows with Python 3.11 to 3.14, builds the wheel and
  checks its contents and the installed command. Dependabot keeps the pinned actions up to
  date.
- The README now covers every rule, the profile format and its messages, each command with
  exit codes and real sample output, the Python API, recipes, the threat model, limits with
  examples, and privacy and network use. `examples/profile.example.json` and `CHECKLIST.md`
  are new.
- The tests are split by concern and cover each scrubber rule, every error path, encodings,
  adversarial input, false alarms, known limits, worst-case timing and the README itself.

## 0.1.0

The first version.

- A local profile of personal details, and `sanitize` / `rehydrate` to swap them for
  placeholders and back, with an optional allow-list.
- JSON-aware sanitising (keys, strings, numbers, JSON Lines), and a re-check that refuses to
  write output if a value is still present behind JSON escapes.
- `check`, which reports secret patterns and profile values, with JSON escapes decoded.
- `scrub`, which keeps the human prompts of an agent transcript, removes harness tags and
  replaces secrets with 11 ordered rules.
- Profiles with unknown keys, duplicate keys, non-string values, colliding custom fields or
  no values are refused. Piped input is read as strict UTF-8.
