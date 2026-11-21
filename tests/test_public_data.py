import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import download_public_data as dl  # noqa: E402

from src.evaluation.public_check import check, to_markdown  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _fake_archive(path: Path, chunks: int = 3, per_chunk: int = 10) -> Path:
    """Archive au même format que celle de flaws.cloud : N fichiers .json.gz de {Records}."""
    with tarfile.open(path, "w") as tar:
        for n in range(chunks):
            records = [
                {"eventID": f"{n}-{i}", "eventTime": f"2020-0{n + 1}-0{i % 9 + 1}T10:00:00Z"}
                for i in range(per_chunk)
            ]
            data = gzip.compress(json.dumps({"Records": records}).encode("utf-8"))
            info = tarfile.TarInfo(f"flaws_cloudtrail_logs/flaws_cloudtrail{n:02d}.json.gz")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_sample_takes_events_from_every_file(tmp_path):
    archive = _fake_archive(tmp_path / "a.tar")
    out = tmp_path / "sample.json"
    info = dl.build_sample(archive, out, max_events=9)
    records = json.loads(out.read_text(encoding="utf-8"))["Records"]
    assert info["files"] == 3 and info["events"] == len(records) == 9
    assert {r["eventID"].split("-")[0] for r in records} == {"0", "1", "2"}
    assert info["first"] < info["last"]


def test_empty_archive_is_refused(tmp_path):
    empty = tmp_path / "empty.tar"
    with tarfile.open(empty, "w"):
        pass
    with pytest.raises(ValueError):
        dl.build_sample(empty, tmp_path / "s.json", 10)


def test_download_from_local_file_and_skip_if_present(tmp_path):
    archive = _fake_archive(tmp_path / "src.tar")
    dest = tmp_path / "public" / "copy.tar"
    dl.download(archive.as_uri(), dest)
    assert dest.exists() and dest.stat().st_size == archive.stat().st_size
    dest.write_bytes(b"marker")
    dl.download(archive.as_uri(), dest)  # déjà présent : pas de retéléchargement
    assert dest.read_bytes() == b"marker"


def test_check_counts_rejects_and_alerts():
    result = check(FIXTURES / "cloudtrail_sample.json")
    assert result["total"] == result["valid"] + result["rejected"] > 0
    assert result["alerts"] > 0 and result["alerts_by_rule"]
    assert result["windows"] > 0


def test_check_reports_rejected_records(tmp_path):
    logs = tmp_path / "logs.json"
    logs.write_text(json.dumps({"Records": [{"eventID": "x"}]}), encoding="utf-8")
    result = check(logs)
    assert result["rejected"] == 1 and result["valid"] == 0
    assert result["reject_reasons"] and result["alerts"] == 0


def test_markdown_report_has_sections():
    report = to_markdown(check(FIXTURES / "cloudtrail_sample.json"), "test")
    assert "## Alertes par règle" in report and "## Événements les plus fréquents" in report
