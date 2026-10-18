import httpx
from sqlmodel import Session
from app.database import engine
from app.models import CVE

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_ids():
    """Descarga el JSON de KEV y devuelve un set con los cveID."""
    response = httpx.get(KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    ids = set()
    for item in data["vulnerabilities"]:
        ids.add(item["cveID"])
    return ids
    


def mark_kev(kev_ids):
    """Marca in_kev=True en los CVEs de la base que estén en la lista."""
    with Session(engine) as session:
        for cve_id in kev_ids:
            cve = session.get(CVE, cve_id)
            if cve:
                cve.in_kev = True
                session.add(cve)
        session.commit()


def main():
    kev_ids = fetch_kev_ids()
    print(f"KEV tiene {len(kev_ids)} CVEs explotados")
    mark_kev(kev_ids)
    print("KEV aplicado.")


if __name__ == "__main__":
    main()