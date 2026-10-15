import httpx
from datetime import datetime, timezone
from sqlmodel import Session, select
from app.database import engine
from app.models import CVE
from app.database import engine, create_db_and_tables


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_english_description(cve_data):
    """Busca la descripción en inglés dentro de la lista de descriptions."""
    for desc in cve_data['descriptions']:
        if desc['lang'] == 'en':
            return desc['value']
    return ''


def get_cvss_score(cve_data):
    """Saca el baseScore del CVSS. Devuelve None si no existe."""
    try:
        return cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        return None


def fetch_batch(start_index, results_per_page=100):
    """Pide un lote de CVEs a la NVD."""
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}
    response = httpx.get(NVD_URL, params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def save_cves(vulnerabilities):
    """Guarda una lista de vulnerabilidades en la base, sin duplicados."""
    with Session(engine) as session:
        for item in vulnerabilities:
            cve_data = item["cve"]
            cve_id = cve_data["id"]

            # Evita duplicados: si ya existe, lo salta
            existing = session.get(CVE, cve_id)
            if existing:
                continue

            cve = CVE(
                cve_id=cve_id,
                description=get_english_description(cve_data),
                cvss_score=get_cvss_score(cve_data),
                published= datetime.fromisoformat(cve_data["published"]).replace(tzinfo=timezone.utc),
            )
            session.add(cve)
        session.commit()


def main():
    create_db_and_tables()
    total_to_fetch = 500   # para empezar, 500 CVEs
    per_page = 100
    for start in range(0, total_to_fetch, per_page):
        print(f"Descargando desde {start}...")
        data = fetch_batch(start, per_page)
        vulns = data["vulnerabilities"]
        save_cves(vulns)
    print("Ingesta completada.")


if __name__ == "__main__":
    main()