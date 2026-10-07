import csv
import io

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from models import Base, Indicator, SessionLocal, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatLens")

REQUIRED_COLUMNS = {"type", "value", "source", "first_seen", "count", "malware_family"}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ingest_rows(rows, db: Session):
    # Pass 1: total the rows inside this file per indicator
    # (a duplicate row inside one file adds its count)
    agg = {}
    rows_read = 0
    for row in rows:
        rows_read += 1
        key = (row["type"].strip().lower(), row["value"].strip().lower())
        count = int(row["count"] or 1)
        first_seen = row["first_seen"].strip()
        if key in agg:
            agg[key]["count"] += count
            if first_seen < agg[key]["first_seen"]:
                agg[key]["first_seen"] = first_seen
        else:
            agg[key] = {
                "count": count,
                "first_seen": first_seen,
                "source": row["source"].strip(),
                "malware_family": row["malware_family"].strip(),
            }

    # Pass 2: compare with the database.
    # Keep the larger count, so re-uploading the same file changes nothing.
    inserted = 0
    for (ioc_type, value), a in agg.items():
        existing = db.query(Indicator).filter_by(type=ioc_type, value=value).first()
        if existing:
            existing.times_seen = max(existing.times_seen or 0, a["count"])
            if a["first_seen"] < existing.first_seen:
                existing.first_seen = a["first_seen"]
        else:
            db.add(
                Indicator(
                    type=ioc_type,
                    value=value,
                    source=a["source"],
                    first_seen=a["first_seen"],
                    times_seen=a["count"],
                    malware_family=a["malware_family"],
                )
            )
            inserted += 1
    db.commit()
    return {"rows_read": rows_read, "inserted": inserted, "duplicates_merged": rows_read - inserted}


def read_csv_text(text: str):
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
        raise HTTPException(400, f"CSV must contain columns: {sorted(REQUIRED_COLUMNS)}")
    return list(reader)


@app.get("/")
def health():
    return {"status": "ThreatLens is running"}


@app.post("/ingest/sample")
def ingest_sample(db: Session = Depends(get_db)):
    with open("data/sample_feed.csv", encoding="utf-8-sig") as f:
        rows = read_csv_text(f.read())
    return ingest_rows(rows, db)


@app.post("/ingest")
async def ingest_upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    text = (await file.read()).decode("utf-8-sig")
    return ingest_rows(read_csv_text(text), db)


@app.get("/indicators")
def list_indicators(db: Session = Depends(get_db)):
    return [i.to_dict() for i in db.query(Indicator).order_by(Indicator.id).all()]


@app.post("/reset")
def reset(db: Session = Depends(get_db)):
    db.query(Indicator).delete()
    db.commit()
    return {"status": "all indicators deleted"}


import json
from scoring import score_indicator


@app.post("/score")
def score_all(db: Session = Depends(get_db)):
    by_severity = {"High": 0, "Medium": 0, "Low": 0}
    for ind in db.query(Indicator).all():
        r = score_indicator(ind)
        ind.score = r["score"]
        ind.severity = r["severity"]
        ind.tags = r["tags"]
        ind.score_breakdown = r["breakdown"]
        by_severity[r["severity"]] += 1
    db.commit()
    return {"scored": sum(by_severity.values()), "by_severity": by_severity}


@app.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    ind = db.get(Indicator, indicator_id)
    if not ind:
        raise HTTPException(404, "Indicator not found")
    data = ind.to_dict()
    data["breakdown"] = json.loads(ind.score_breakdown) if ind.score_breakdown else []
    return data


from typing import Literal
from pydantic import BaseModel


class ReviewIn(BaseModel):
    status: Literal["Pending", "Approved", "Rejected", "Escalated"]
    note: str = ""


@app.patch("/indicators/{indicator_id}")
def review_indicator(indicator_id: int, review: ReviewIn, db: Session = Depends(get_db)):
    ind = db.get(Indicator, indicator_id)
    if not ind:
        raise HTTPException(404, "Indicator not found")
    ind.status = review.status
    ind.analyst_note = review.note
    db.commit()
    return ind.to_dict()


@app.get("/queue")
def review_queue(limit: int = 10, db: Session = Depends(get_db)):
    pending = (
        db.query(Indicator)
        .filter(Indicator.status == "Pending")
        .order_by(Indicator.score.desc())
        .limit(limit)
        .all()
    )
    return [i.to_dict() for i in pending]


@app.get("/summary")
def summary(db: Session = Depends(get_db)):
    items = db.query(Indicator).all()
    by_severity = {"High": 0, "Medium": 0, "Low": 0}
    by_status = {"Pending": 0, "Approved": 0, "Rejected": 0, "Escalated": 0}
    by_type = {}
    for i in items:
        if i.severity in by_severity:
            by_severity[i.severity] += 1
        by_status[i.status] = by_status.get(i.status, 0) + 1
        by_type[i.type] = by_type.get(i.type, 0) + 1
    return {
        "total": len(items),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
    }


from dlp import scan_text


class DLPIn(BaseModel):
    text: str


@app.post("/dlp/scan")
def dlp_scan(body: DLPIn):
    return scan_text(body.text)


from fastapi.responses import Response
from report import build_report


@app.get("/report")
def get_report(db: Session = Depends(get_db)):
    items = db.query(Indicator).all()
    if not any(i.score is not None for i in items):
        raise HTTPException(400, "Ingest and score first: POST /ingest/sample, then POST /score")
    pdf = build_report(items)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=ThreatLens_Report.pdf"},
    )


from stix_export import build_bundle

VALID_STATUS = {"approved", "pending", "rejected", "escalated", "all"}


@app.get("/export/stix")
def export_stix(status: str = "Approved", min_score: int = 0, db: Session = Depends(get_db)):
    if status.lower() not in VALID_STATUS:
        raise HTTPException(400, "status must be one of: Approved, Pending, Rejected, Escalated, all")
    q = db.query(Indicator).filter(Indicator.score.isnot(None), Indicator.score >= min_score)
    if status.lower() != "all":
        q = q.filter(Indicator.status == status.capitalize())
    items = q.order_by(Indicator.score.desc()).all()
    if not items:
        raise HTTPException(404, "No indicators match. Approve some first, or use ?status=all")
    bundle = build_bundle(items)
    return Response(
        content=bundle.serialize(pretty=True),
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": "attachment; filename=threatlens_bundle.json"},
    )


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:5176",
        "http://localhost:5177",
        "http://127.0.0.1:5177",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)
