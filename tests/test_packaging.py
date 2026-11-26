"""The built wheel and the installed command.

These tests need a built wheel and an installed package, so they are skipped in a normal run.
CI builds the wheel, installs it, and runs this file with AIRGAP_WHEEL_DIR (the folder that
holds the wheel) and AIRGAP_INSTALLED=1 set.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
import zipfile
from email.parser import Parser
from pathlib import Path

import support  # noqa: F401  (puts src on the path)

from llm_pii_airgap import __version__

WHEEL_DIR = os.environ.get("AIRGAP_WHEEL_DIR")
INSTALLED = os.environ.get("AIRGAP_INSTALLED") == "1"
PACKAGE_FILES = {"__init__.py", "cli.py", "scrubber.py", "tokenizer.py"}


@unittest.skipUnless(WHEEL_DIR, "set AIRGAP_WHEEL_DIR to the folder holding a built wheel")
class TestWheel(unittest.TestCase):
    def setUp(self) -> None:
        wheels = sorted(Path(WHEEL_DIR).glob("llm_pii_airgap-*.whl"))
        self.assertEqual(len(wheels), 1, wheels)
        self.wheel = zipfile.ZipFile(wheels[0])
        self.addCleanup(self.wheel.close)

    def test_contains_only_the_package_and_its_metadata(self) -> None:
        dist_info = f"llm_pii_airgap-{__version__}.dist-info/"
        package = {name.split("/", 1)[1] for name in self.wheel.namelist() if name.startswith("llm_pii_airgap/")}
        self.assertEqual(package, PACKAGE_FILES)
        others = [name for name in self.wheel.namelist()
                  if not name.startswith("llm_pii_airgap/") and not name.startswith(dist_info)]
        self.assertEqual(others, [])

    def test_metadata(self) -> None:
        metadata = Parser().parsestr(self.wheel.read(f"llm_pii_airgap-{__version__}.dist-info/METADATA").decode("utf-8"))
        self.assertEqual(metadata["Name"], "llm-pii-airgap")
        self.assertEqual(metadata["Version"], __version__)
        self.assertEqual(metadata["Requires-Python"], ">=3.11")
        self.assertIsNone(metadata["Requires-Dist"])
        entry_points = self.wheel.read(f"llm_pii_airgap-{__version__}.dist-info/entry_points.txt").decode("utf-8")
        self.assertIn("llm-pii-airgap = llm_pii_airgap.cli:main", entry_points)


@unittest.skipUnless(INSTALLED, "set AIRGAP_INSTALLED=1 after installing the package")
class TestInstalledCommand(unittest.TestCase):
    def run_command(self, *args: str) -> subprocess.CompletedProcess:
        command = shutil.which("llm-pii-airgap")
        self.assertIsNotNone(command, "llm-pii-airgap is not on PATH")
        return subprocess.run([command, *args], capture_output=True, text=True, encoding="utf-8", timeout=60)

    def test_version(self) -> None:
        proc = self.run_command("--version")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, f"llm-pii-airgap {__version__}"))

    def test_help(self) -> None:
        proc = self.run_command("--help")
        self.assertEqual(proc.returncode, 0)
        for command in ("scrub", "sanitize", "rehydrate", "check"):
            self.assertIn(command, proc.stdout)


if __name__ == "__main__":
    unittest.main()
