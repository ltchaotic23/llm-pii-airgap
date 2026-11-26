# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open this repository's
**Security** tab and choose **Report a vulnerability**. Please don't open a public issue
for them.

It helps to include what you found, a small input that shows it, what you expected and
what happened, and your Python version and operating system. Use made-up values only,
never real secrets or personal details.

Examples of what counts:

- a way to make any command print a matched value, a profile value or a secret
- input that makes a profile value or a secret get through `sanitize`, `scrub` or `check`
  silently (exit code 0, or `check` reporting clean)
- `rehydrate` restoring a placeholder that wasn't allowed
- crafted input that makes the tool crash or hang

A secret format or personal detail that the scrubber simply doesn't know about isn't a
vulnerability, and neither are the documented limits in the README. Please open an
ordinary issue for them, with a made-up example.

## Supported versions

Only the latest version on the default branch gets fixes.
