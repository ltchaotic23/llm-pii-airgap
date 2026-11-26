"""Each scrubber rule: what it catches, what it must leave alone, and rule order."""

from __future__ import annotations

import json
import unittest

from support import FAKE_SECRET as _FAKE_SECRET, REDACT_RULES, j, redact_secrets


class TestAllRules(unittest.TestCase):
    def test_all_eleven_redaction_rules(self) -> None:
        # Construct synthetic fixtures dynamically so secret scanners never flag test code.
        fake_priv = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END " + "RSA PRIVATE KEY-----"
        fake_discord = "MTI" + "AbCdEfGhIjKlMnOpQrStUvW" + ".XaBcDe." + "1234567890abcdefGHIJKLMNOPQRstuvwx"
        fake_gh = "ghp_" + ("A1b2C3d4E5" * 4)
        fake_google = "AIza" + ("0123456789abcde" * 2) + "12345"
        fake_sk = "sk-" + ("abc123XYZ_" * 3)
        fake_url = "https://" + "alice:superpass123" + "@registry.example.invalid/pkg"
        fake_proxy = "vless://" + "11112222-3333-4444-5555-666677778888@203.0.113.10:443?security=reality#test"
        fake_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        fake_long = "Z9" + ("aB3dE6fG8h" * 4) + "=="

        sample = "\n".join(
            [
                fake_priv,
                f"bot={fake_discord}",
                f"gh={fake_gh} google={fake_google} openai={fake_sk}",
                f"repo={fake_url}",
                f"node={fake_proxy}",
                f"id={fake_uuid}",
                "mail=dev.user@example.invalid",
                "host=198.51.100.42",
                "tel=+1 202 555 0178",
                "password = my_local_dev_pw",
                f"blob={fake_long}",
            ]
        )
        scrubbed, counts = redact_secrets(sample)
        expected_tags = [
            "<PRIVATE_KEY>",
            "<DISCORD_TOKEN>",
            "<API_KEY>",
            "<URL_WITH_CREDS>",
            "<PROXY_URI>",
            "<UUID>",
            "<EMAIL>",
            "<IP>",
            "<PHONE>",
            "<SECRET>",
            "<LONG_TOKEN>",
        ]
        for tag in expected_tags:
            self.assertIn(tag, scrubbed)
            self.assertGreaterEqual(counts.get(tag, 0), 1)
        self.assertNotIn("superpass123", scrubbed)
        self.assertNotIn("my_local_dev_pw", scrubbed)
        self.assertNotIn("198.51.100.42", scrubbed)


class TestSecretRuleCoverage(unittest.TestCase):
    """The <SECRET> rule must fire on the shapes secrets really arrive in."""

    def test_secret_names_inside_longer_names_json_headers_and_flags(self) -> None:
        v = _FAKE_SECRET
        samples = [
            f"DB_PASSWORD={v}",
            f"OPENAI_API_KEY={v}",
            f"GITHUB_TOKEN={v}",
            f"access_token={v}",
            f"client_secret: {v}",
            f"export SECRET_KEY={v}",
            f"passphrase={v}",
            f"SMTP_PASS={v}",
            f"STRIPE_KEY={v}",
            f'{{"password": "{v}", "user": "bob"}}',
            f'{{"apiKey":"{v}"}}',
            f'{{"accessToken": "{v}"}}',
            f'{{\\"password\\": \\"{v} two\\"}}',
            f'os.environ["API_KEY"] = "{v}"',
            f'password == "{v}"',
            f"token => {v}",
            f"password: ={v}",
            f"Authorization: Bearer {v}",
            f"Authorization: Basic {v}==",
            f'"Authorization": "Bearer {v}"',
            f"send Bearer abc123def456ghi789{v} now",
            f"mysql -u root --password {v}",
            f"tool --api-key {v} --verbose",
            f"https://api.example.invalid/x?access_token={v}&page=1",
            f"passwd={v}",
            f"pwd={v}",
            f"credential={v}",
            f"access_key={v}",
            f"private_key={v}",
            f"auth_key={v}",
            f"signing_key={v}",
            f"encryption_key={v}",
            f"password: |\n  {v}_line1\n  {v}_line2",
            f"secret: >-\n  {v}_folded",
            f"Authorization: Token {v}",
            f"Authorization: ApiKey {v}",
            f'curl -H "Authorization: Token {v}" https://example.invalid',
            f'api_key = os.getenv("API_KEY", "{v}_default")',
            f'x = os.environ.get("DB_PASSWORD", "{v} two")',
            f'db_password = app_password = "{v}"',
            f'db_password=app_password="{v}"',
            f'def refresh(token: str = "{v}"):',
            f'cli --api-key "{v} two" --verbose',
            f"password: 'it''s {v}'",
            f'PASSWORD="first_line\n{v}_second_line"',
            f'password = r"{v} two"',
            f"password = `{v} two`",
            f'password = "unclosed {v} two\nnext_line_safe',
            f"DB_PASSWORD=true-{v}",
            f"password: none-{v}",
            f"DB_PASSWORD=True.{v}_123",
            f"db.password.prod={v}",
            f'oauth_access_token_for_staging_environment_primary_cluster_a: "{v}"',
        ]
        for sample in samples:
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                # A second pass finds nothing, so `check` on scrubbed output reports clean.
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))
        self.assertEqual(
            redact_secrets(f"password: |\n  {v}_1\n  {v}_2\nusername: bob")[0],
            "password: <SECRET>\nusername: bob",
        )
        self.assertEqual(
            redact_secrets(f'password = "unclosed {v}\nnext_line_safe')[0],
            "password = <SECRET>\nnext_line_safe",
        )

    def test_secret_named_parent_never_swallows_the_next_key(self) -> None:
        # Taking a nested key as the "value" would redact the key and leave the secret bare.
        v = _FAKE_SECRET
        samples = [
            f"credentials:\n  password: {v}",
            f"secret:\n  api_key: {v}",
            f"credentials:\n  DB_PASSWORD={v}",
            json.dumps({"token": {"access_token": v}}),
            json.dumps({"token": {"access_token": v}}, indent=2),
            json.dumps({"credentials": [{"password": v}]}),
            f"token = {{\n  'password': '{v}'\n}}",
        ]
        for sample in samples:
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))
        self.assertEqual(
            redact_secrets(f"credentials:\n  password: {v}")[0],
            "credentials:\n  password: <SECRET>",
        )

        # A plain value on the following line is still redacted: base64 padding and a YAML list item included.
        for sample in (
            f"password:\n  {v}",
            f"password:\r\n{v}==",
            f"password:\n  - {v}",
            f"token: https://x.example.invalid/{v}",
        ):
            with self.subTest(sample=sample.replace(v, "<value>")):
                scrubbed, counts = redact_secrets(sample)
                self.assertNotIn(v, scrubbed)
                self.assertEqual(counts, {"<SECRET>": 1})
                self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))

    def test_key_name_is_kept_and_quoted_value_removed_whole(self) -> None:
        v = _FAKE_SECRET
        self.assertEqual(redact_secrets(f"DB_PASSWORD={v}")[0], "DB_PASSWORD=<SECRET>")
        self.assertEqual(redact_secrets(f'password = "{v} two words"')[0], "password = <SECRET>")
        self.assertEqual(redact_secrets(f"password = '{v} two words'")[0], "password = <SECRET>")
        self.assertEqual(
            redact_secrets(f'{{"password": "{v}", "user": "bob"}}')[0],
            '{"password": <SECRET>, "user": "bob"}',
        )
        self.assertEqual(redact_secrets(f"tool --api-key {v} --verbose")[0], "tool --api-key <SECRET> --verbose")

    def test_ordinary_words_and_placeholders_are_left_alone(self) -> None:
        for sample in (
            "max_tokens = 4096",
            '"input_tokens": 1234, "output_tokens": 55',
            "MAX_TOKENS=4096",
            "tokenizer = PIIAirgap(profile)",
            '"token": null',
            "use_secret: false",
            "the secretary: Jane",
            "tests PASSED: 12",
            "passwords: see the vault",
            "--max-tokens 100",
            "--no-password --verbose",
            "basic authentication is fine",
            "API_KEY=<YOUR_API_KEY>",
            '"api_key": "<API_KEY>"',
            'password: "<SECRET>"',
            "use_secret: true",
            "password = None",
            "token = none",
            'TOKENIZER = AutoTokenizer.from_pretrained("bert-base-uncased")',
            'SECRETARY = "Alex"',
            "PASS_RATE = 0.95",
            'token_type = "Bearer"',
            'api_key = os.getenv("API_KEY", None)',
            "Authorization: Token <API_KEY>",
        ):
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample), (sample, {}))


# Fake values, assembled at run time. FAKE marks them where the format allows it.
PEM_BODY = j("MIIEowIBAAKCAQEA", "FAKE", "\n", "FAKEFAKE")
DISCORD = j("M", "FAKE" * 6, ".", "FAKEab", ".", "FAKE" * 7)  # 25 . 6 . 28 characters
UUID_TEXT = j("123e4567", "-e89b-12d3-a456-", "426614174000")


def pem(kind: str, body: str = PEM_BODY) -> str:
    return j("-----BEGIN ", kind, "-----\n", body, "\n-----END ", kind, "-----")


class RuleTestCase(unittest.TestCase):
    def assert_redacted(self, sample: str, expected: str, counts: dict[str, int]) -> None:
        with self.subTest(sample=sample):
            self.assertEqual(redact_secrets(sample), (expected, counts))

    def assert_unchanged(self, *samples: str) -> None:
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(redact_secrets(sample), (sample, {}))


class TestRuleOrder(unittest.TestCase):
    def test_rules_run_most_specific_first(self) -> None:
        self.assertEqual(
            [placeholder for placeholder, _ in REDACT_RULES],
            ["<PRIVATE_KEY>", "<DISCORD_TOKEN>", "<API_KEY>", "<URL_WITH_CREDS>", "<PROXY_URI>", "<UUID>",
             "<EMAIL>", "<IP>", "<PHONE>", "<SECRET>", "<LONG_TOKEN>"],
        )

    def test_a_second_pass_finds_nothing(self) -> None:
        sample = "\n".join([
            pem("RSA PRIVATE KEY"), f"bot {DISCORD}", j("use sk-", "FAKE" * 5), j("https://", "u:FAKE", "@example.invalid/x"),
            j("vless://", UUID_TEXT, "@203.0.113.10:443"), f"id {UUID_TEXT}", "mail alex@example.invalid", "host 192.0.2.1",
            "call +1 202 555 0143", f'{{"password": "{_FAKE_SECRET} two"}}', j("blob Z9", "aB3dE6fG8h" * 4),
        ])
        scrubbed, counts = redact_secrets(sample)
        self.assertEqual(len(counts), len(REDACT_RULES))
        self.assertEqual(redact_secrets(scrubbed), (scrubbed, {}))


class TestPrivateKey(RuleTestCase):
    def test_catches_key_blocks(self) -> None:
        for kind in ("RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            self.assert_redacted(f"key:\n{pem(kind)}\ndone", "key:\n<PRIVATE_KEY>\ndone", {"<PRIVATE_KEY>": 1})

    def test_an_unclosed_header_before_a_whole_block_is_swallowed_with_it(self) -> None:
        header = j("-----BEGIN RSA ", "PRIVATE KEY-----")
        text = f"{header}\nFIRSTBODYFAKE\nnote\n{pem('RSA PRIVATE KEY', 'SECONDBODYFAKE')}\nafter"
        self.assert_redacted(text, "<PRIVATE_KEY>\nafter", {"<PRIVATE_KEY>": 1})

    def test_leaves_public_material_alone(self) -> None:
        self.assert_unchanged(pem("PUBLIC KEY", "MIIBFAKE"), pem("CERTIFICATE", "MIIBFAKE"))

    def test_runs_before_the_rules_that_would_split_the_block(self) -> None:
        body = "alex.example@example.invalid 192.0.2.10 " + "aB3dE6fG8h" * 5
        self.assert_redacted(pem("RSA PRIVATE KEY", body), "<PRIVATE_KEY>", {"<PRIVATE_KEY>": 1})


class TestDiscordToken(RuleTestCase):
    def test_catches_the_three_part_token(self) -> None:
        self.assert_redacted(f"bot {DISCORD} ready", "bot <DISCORD_TOKEN> ready", {"<DISCORD_TOKEN>": 1})
        tail_dash = j("M", "FAKE" * 6, ".FAKEab.", "FAKE" * 6, "FA-")
        self.assert_redacted(f"bot {tail_dash} ready", "bot <DISCORD_TOKEN> ready", {"<DISCORD_TOKEN>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged(
            "A" + DISCORD[1:],  # must start with M, N or O
            DISCORD.replace(".FAKEab.", ".FAKEa."),  # middle part must be 6 characters
        )

    def test_runs_before_the_generic_rules(self) -> None:
        # Without it, the dotted parts would be left for <EMAIL> or <LONG_TOKEN> to half-match.
        self.assert_redacted(f"token={DISCORD}", "token=<DISCORD_TOKEN>", {"<DISCORD_TOKEN>": 1})


class TestApiKey(RuleTestCase):
    def test_catches_known_prefixes(self) -> None:
        for key in (
            j("sk-", "FAKE" * 5),
            j("sk-proj-", "FAKE_" * 4),
            j("AI", "za", "FAKE" * 8, "abc"),
            *(j("gh", kind, "_", "FAKE" * 9) for kind in "pousr"),
            *(j("xox", kind, "-", "FAKE-12345") for kind in "abpr"),
            j("AK", "IA", "FAKE" * 4),
            j("AI", "za", "FAKE" * 8, "FA-"),
            j("sk-", "FAKE" * 3, "FAK-"),
            j("xox", "b-", "FAKE12345-"),
        ):
            self.assert_redacted(f"use {key} here", "use <API_KEY> here", {"<API_KEY>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged(
            j("sk-", "short"),
            j("AK", "IA", "FAKEFAKEFAKEFAK"),  # 15 characters after the prefix, not 16
            "task-manager-component-tests",
            "risk-assessment-framework-documentation",
            j("gh", "x_", "FAKE" * 9),
        )

    def test_secret_rule_leaves_the_placeholder_alone(self) -> None:
        key = j("gh", "p_", "FAKE" * 9)
        self.assert_redacted(f"GITHUB_TOKEN={key}", "GITHUB_TOKEN=<API_KEY>", {"<API_KEY>": 1})
        self.assert_redacted(f"Authorization: Bearer {key}", "Authorization: Bearer <API_KEY>", {"<API_KEY>": 1})
        self.assert_redacted(json.dumps({"token": key}), '{"token": "<API_KEY>"}', {"<API_KEY>": 1})


class TestUrlWithCredentials(RuleTestCase):
    def test_catches_passwords_in_urls(self) -> None:
        for url in (
            j("https://", "exampleuser:FAKE", "@registry.example.invalid/simple"),
            j("postgres://", "app:FAKE", "@db.example.invalid:5432/app"),
            j("HTTPS://", "exampleuser:FAKE", "@registry.example.invalid/simple"),
            j("git+ssh://", "exampleuser:FAKE", "@git.example.invalid/repo.git"),
        ):
            self.assert_redacted(f"pip install --index-url {url} pkg", "pip install --index-url <URL_WITH_CREDS> pkg",
                                 {"<URL_WITH_CREDS>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged(
            "https://registry.example.invalid/simple",
            "ssh://git.example.invalid:2222/repo",
            "see https://example.invalid/a:b/c",
        )

    def test_runs_before_email(self) -> None:
        url = j("https://", "exampleuser:FAKE", "@example.invalid")
        self.assert_redacted(url, "<URL_WITH_CREDS>", {"<URL_WITH_CREDS>": 1})


class TestProxyUri(RuleTestCase):
    def test_catches_proxy_links(self) -> None:
        for scheme in ("vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2"):
            link = j(scheme, "://", "FAKE", "@203.0.113.10:443?security=tls#node")
            self.assert_redacted(f"node {link}", "node <PROXY_URI>", {"<PROXY_URI>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged("sss://example", "vlessx://example", "https://example.invalid/vless")

    def test_runs_before_uuid_and_ip(self) -> None:
        link = j("vless://", UUID_TEXT, "@203.0.113.10:443")
        self.assert_redacted(link, "<PROXY_URI>", {"<PROXY_URI>": 1})


class TestUuid(RuleTestCase):
    def test_catches_uuids(self) -> None:
        for value in (UUID_TEXT, UUID_TEXT.upper()):
            self.assert_redacted(f"id={value}", "id=<UUID>", {"<UUID>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged(UUID_TEXT[1:], UUID_TEXT.replace("e", "g"))

    def test_runs_before_email(self) -> None:
        # The UUID goes first, which leaves only the domain of a UUID-shaped address behind.
        self.assert_redacted(f"{UUID_TEXT}@example.invalid", "<UUID>@example.invalid", {"<UUID>": 1})


class TestEmail(RuleTestCase):
    def test_catches_addresses(self) -> None:
        for value in ("alex.example@example.invalid", "first+tag@sub.example.org", "a_b-c@example.com"):
            self.assert_redacted(f"mail {value}.", "mail <EMAIL>.", {"<EMAIL>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged("@decorator", "user@localhost", "a@b", "name at example dot org")

    def test_keeps_leading_punctuation(self) -> None:
        self.assert_redacted("--alex@example.invalid", "--<EMAIL>", {"<EMAIL>": 1})

    def test_runs_before_secret(self) -> None:
        self.assert_redacted("password: alex@example.invalid", "password: <EMAIL>", {"<EMAIL>": 1})


class TestIp(RuleTestCase):
    def test_catches_ipv4(self) -> None:
        for value in ("203.0.113.10", "192.0.2.255", "198.51.100.7"):
            self.assert_redacted(f"host {value}:8080", "host <IP>:8080", {"<IP>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged("1.2.3", "version 1.26.4", "2001:db8::1")


class TestPhone(RuleTestCase):
    def test_catches_international_numbers(self) -> None:
        for value in ("+1 202 555 0143", "+1-202-555-0143", "+1 (202) 555 0143", "+12025550143"):
            self.assert_redacted(f"call {value} now", "call <PHONE> now", {"<PHONE>": 1})
        self.assert_redacted("++1 (202) 555-0143", "+<PHONE>", {"<PHONE>": 1})
        self.assert_redacted("++1 202 555 0143", "+<PHONE>", {"<PHONE>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged("+123", "+1 2 3", "ext 202 555 0143")


class TestLongToken(RuleTestCase):
    def test_catches_long_mixed_strings(self) -> None:
        token = j("Z9", "aB3dE6fG8h" * 4, "==")
        self.assert_redacted(f"blob={token} end", "blob=<LONG_TOKEN> end", {"<LONG_TOKEN>": 1})
        self.assert_redacted(f"x /{token}", "x /<LONG_TOKEN>", {"<LONG_TOKEN>": 1})

    def test_near_misses(self) -> None:
        self.assert_unchanged(
            j("Z9", "aB3dE6fG8h" * 3, "aB3dE6f"),  # 39 characters
            "a" * 60,  # no digit
            "1" * 60,  # no letter
            "a-" * 30,  # no digit
        )

    def test_runs_last(self) -> None:
        token = j("Z9", "aB3dE6fG8h" * 4)
        self.assert_redacted(f"password={token}", "password=<SECRET>", {"<SECRET>": 1})
        key = j("gh", "p_", "FAKE" * 9, "1234")
        self.assert_redacted(key, "<API_KEY>", {"<API_KEY>": 1})


if __name__ == "__main__":
    unittest.main()
