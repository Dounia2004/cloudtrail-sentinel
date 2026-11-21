"""Télécharge le jeu public de logs CloudTrail de flaws.cloud et en extrait un échantillon.

Source : Summit Route (Scott Piper), « Public dataset of CloudTrail logs from flaws.cloud »,
octobre 2020. Environ 1,9 million d'événements anonymisés (2017-2020), 240 Mo compressés,
distribués en 20 fichiers `flaws_cloudtrail_logs/flaws_cloudtrail00.json.gz` à `19`, chacun
au format {"Records": [...]}. La licence n'est pas précisée par l'auteur : le jeu est donc
téléchargé à la demande dans data/public/ (ignoré par Git) et n'est jamais copié dans le dépôt.

Utilisation :
    python scripts/download_public_data.py                    # échantillon de 50 000 événements
    python scripts/download_public_data.py --max-events 200000
    python scripts/download_public_data.py --force            # retélécharge l'archive
Ensuite : python -m src.evaluation.public_check
"""
import argparse
import gzip
import json
import tarfile
import urllib.request
from pathlib import Path

URL = "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar"
DEST = Path("data/public")
ARCHIVE = DEST / "flaws_cloudtrail_logs.tar"
SAMPLE = DEST / "flaws_cloudtrail_sample.json"


def download(url: str, dest: Path, force: bool = False) -> Path:
    if dest.exists() and not force:
        print(f"Archive déjà présente : {dest}")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    print(f"Téléchargement de {url} ...")

    def progress(blocks: int, block_size: int, total: int) -> None:
        if total > 0 and blocks % 400 == 0:
            done = min(blocks * block_size, total)
            print(f"  {done / 1e6:.0f} / {total / 1e6:.0f} Mo", flush=True)

    urllib.request.urlretrieve(url, tmp, progress)
    tmp.replace(dest)
    return dest


def build_sample(archive: Path, out: Path, max_events: int) -> dict:
    """Prend les premiers événements de chaque fichier pour couvrir toute la période.

    L'archive est lue en flux, sans extraction sur le disque.
    """
    with tarfile.open(archive) as tar:
        members = sorted(
            (m for m in tar.getmembers() if m.isfile() and m.name.endswith(".json.gz")),
            key=lambda m: m.name,
        )
        if not members:
            raise ValueError("Aucun fichier .json.gz dans l'archive.")
        per_file = max(max_events // len(members), 1)
        records = []
        for member in members:
            with gzip.open(tar.extractfile(member), "rt", encoding="utf-8") as handle:
                chunk = json.load(handle).get("Records", [])
            records.extend(chunk[:per_file])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"Records": records}), encoding="utf-8")
    times = sorted(r["eventTime"] for r in records if "eventTime" in r)
    return {
        "files": len(members),
        "events": len(records),
        "first": times[0] if times else None,
        "last": times[-1] if times else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Jeu public de logs CloudTrail (flaws.cloud)")
    parser.add_argument("--url", default=URL, help="adresse de l'archive (file:// accepté)")
    parser.add_argument("--max-events", type=int, default=50000)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    archive = download(args.url, ARCHIVE, args.force)
    info = build_sample(archive, SAMPLE, args.max_events)
    print(
        f"{info['events']} événements extraits de {info['files']} fichiers "
        f"({info['first']} -> {info['last']}) dans {SAMPLE}"
    )
    print("Étape suivante : python -m src.evaluation.public_check")


if __name__ == "__main__":
    main()
