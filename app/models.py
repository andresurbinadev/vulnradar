from datetime import datetime
from sqlmodel import SQLModel, Field


class CVE(SQLModel, table=True):
    cve_id: str = Field(primary_key=True)
    description: str
    cvss_score: float | None = None
    published: datetime | None = None