import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "artifact_tree", Path(__file__).resolve().parents[1] / "verify_artifact_tree.py"
)
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


class ArtifactRoundTripTests(unittest.TestCase):
    def test_nested_files_survive_round_trip_and_changed_bytes_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            source, downloaded = Path(temp) / "source", Path(temp) / "downloaded"
            for root in (source, downloaded):
                (root / "chromium").mkdir(parents=True)
                (root / "chromium/manifest.json").write_bytes(b'{"synthetic":true}')
                (root / "firefox.zip").write_bytes(bytes(range(256)))
            ARTIFACT.verify(source, downloaded)
            (downloaded / "firefox.zip").write_bytes(b"truncated")
            with self.assertRaisesRegex(ValueError, "content changed"):
                ARTIFACT.verify(source, downloaded)

    def test_missing_extra_or_wrapped_files_fail(self):
        for fault in ("missing", "extra", "wrapped"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                source, downloaded = Path(temp) / "source", Path(temp) / "downloaded"
                for root in (source, downloaded):
                    root.mkdir()
                    (root / "manifest.json").write_text("synthetic")
                    (root / "background.js").write_text("synthetic")
                if fault == "missing":
                    (downloaded / "background.js").unlink()
                elif fault == "extra":
                    (downloaded / "unexpected").write_text("synthetic")
                else:
                    (downloaded / "artifact").mkdir()
                    for path in list(downloaded.glob("*.*")):
                        path.rename(downloaded / "artifact" / path.name)
                with self.assertRaisesRegex(ValueError, "paths or content"):
                    ARTIFACT.verify(source, downloaded)

    def test_missing_and_empty_directories_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "empty"):
                ARTIFACT.inventory(temp)
            with self.assertRaisesRegex(ValueError, "missing"):
                ARTIFACT.inventory(Path(temp) / "missing")
