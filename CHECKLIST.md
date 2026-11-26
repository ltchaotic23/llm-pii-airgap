# Before it leaves your machine

A checklist for the moments before you send text to an LLM or publish a dataset of
transcripts. The tool checks some of it for you; the rest needs a person. If any box isn't
ticked, you're not ready yet.

## Before sending text to an LLM

- [ ] Your profile lists every form of your details that the text might contain: a first
      name on its own, a nickname, a username, each way you write your phone number.
      *(The tool only finds exact values. See the README's Limits.)*
- [ ] You ran `sanitize` on a file with `-i`, not on text with `-t` (that stays in your
      shell history), and it exited with 0. *(It refuses to write if a value is still
      there.)*
- [ ] You read the sanitised text. Nothing in it points to you by context: your employer,
      your town, a project name, a unique phrase.
- [ ] You are happy for the provider to learn which kinds of details the prompt contained.
      `[ADDRESS]` says that an address was there.
- [ ] When the reply comes back, you rehydrate with `--allow-from` the prompt you sent, not
      `--allow-all`.
- [ ] The rehydrated output stays on your machine. It contains your real details.

## Before publishing a dataset of transcripts

- [ ] You ran `scrub` on every transcript, then `check -p profile.local.json` on the result.
      *(Expect `<UUID>` counts for the records' own `uuid` values.)*
- [ ] Anything else `check` reported has been dealt with.
- [ ] You read a sample of the output yourself, looking for what patterns miss: names,
      street addresses, home-folder paths, secrets in prose ("the password is ..."), token
      formats the scrubber doesn't know, and secrets split across lines.
- [ ] You looked for over-redaction that would make the dataset less useful (long hashes
      and paths as `<LONG_TOKEN>`, version numbers as `<IP>`) and accept it.
- [ ] The `uuid` and `timestamp` fields are fine to publish. `scrub` copies them as they are.
- [ ] Nobody else's personal details are in the transcripts, or you have their permission.
- [ ] You also ran a dedicated detector for what this tool can't find, such as a PII
      detector or a secret scanner.

## If something leaks anyway

1. Revoke or rotate any secret first. Deleting it afterwards doesn't undo the leak: assume
   it was copied as soon as it left your machine.
2. Then remove what you can (delete the upload, rewrite the dataset), and ask the service
   that holds it to delete cached copies.
