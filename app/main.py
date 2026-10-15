from fastapi import FastAPI

app = FastAPI(title="VulnRadar")


@app.get("/health")
def health():
    return {"status": "ok"}