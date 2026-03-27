from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.entities import Connector, ConnectorJob


def run_connector_sync_jobs(db: Session) -> dict:
    connectors = db.query(Connector).order_by(Connector.id.asc()).all()
    jobs: list[ConnectorJob] = []

    for connector in connectors:
        job = ConnectorJob(
            connector_id=connector.id,
            job_type="sync",
            status="queued",
            message="Job queued for local sync execution.",
        )
        db.add(job)
        db.flush()
        jobs.append(job)

        _execute_sync_job(db, connector, job)

    db.commit()
    return {
        "status": "completed",
        "connectors": len(connectors),
        "jobs_created": len(jobs),
        "jobs_succeeded": len([job for job in jobs if job.status == "ok"]),
        "jobs_skipped": len([job for job in jobs if job.status == "skipped"]),
    }


def list_connector_jobs(db: Session) -> list[ConnectorJob]:
    return db.query(ConnectorJob).order_by(ConnectorJob.id.desc()).all()


def _execute_sync_job(db: Session, connector: Connector, job: ConnectorJob) -> None:
    now = datetime.now(timezone.utc)
    job.status = "running"
    job.started_at = now
    job.message = f"Running local sync for connector type {connector.source_type}."
    db.flush()

    if not connector.enabled:
        connector.last_sync_status = "skipped"
        connector.last_sync_message = "Connector disabled."
        connector.last_sync_at = now
        job.status = "skipped"
        job.message = "Connector disabled. Job skipped."
        job.finished_at = datetime.now(timezone.utc)
        db.flush()
        return

    connector.last_sync_status = "ok"
    connector.last_sync_message = f"Local sync completed for {connector.source_type} connector."
    connector.last_sync_at = now
    job.status = "ok"
    job.message = connector.last_sync_message
    job.finished_at = datetime.now(timezone.utc)
    db.flush()
