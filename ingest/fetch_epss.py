import gzip
import csv
import io
import httpx
from sqlmodel import Session
from app.database import engine
from app.models import CVE

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_epss_scores():
    """Descarga y descomprime el CSV de EPSS. Devuelve un dict {cve_id: score}."""
    response = httpx.get(EPSS_URL, timeout=60, follow_redirects=True)
    response.raise_for_status()

    # Descomprime el .gz en memoria
    decompressed = gzip.decompress(response.content).decode("utf-8")

    scores = {}
    # El CSV tiene 2 líneas de cabecera (un comentario y los nombres de columna)
    reader = csv.DictReader(io.StringIO(decompressed).readlines()[1:])
    for row in reader:
        # TODO: guardar scores[row["cve"]] = float(row["epss"])
        scores[row["cve"]] = float(row["epss"])
    return scores


def apply_epss(scores):
    """Actualiza el epss_score de los CVEs que están en la base."""
    with Session(engine) as session:
        for cve_id, score in scores.items():
            cve = session.get(CVE, cve_id)
            if cve:
                cve.epss_score = score
                session.add(cve)
        session.commit()


def main():
    scores = fetch_epss_scores()
    print(f"EPSS tiene scores para {len(scores)} CVEs")
    apply_epss(scores)
    print("EPSS aplicado.")


if __name__ == "__main__":
    main()