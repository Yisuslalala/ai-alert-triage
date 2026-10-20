def main() -> None:
    import uvicorn

    uvicorn.run("ai_alert_triage.main:app", host="127.0.0.1", port=8000)
