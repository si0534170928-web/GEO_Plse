import os
import json
import asyncio
import uuid
from datetime import datetime
from dotenv import load_dotenv

# FastAPI & API Tools
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Database
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, ForeignKey, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# AI & Scheduling
import openai
from apscheduler.schedulers.background import BackgroundScheduler

# --- 1. הגדרות סביבה ובסיס נתונים ---
load_dotenv()
DATABASE_URL = "sqlite:///./geopulse.db"
engine_db = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_db)
Base = declarative_base()

# --- 2. מודלים של מסד הנתונים ---
class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    date = Column(DateTime, default=datetime.utcnow)
    target_brand = Column(String)
    total_score = Column(Float, default=0.0)
    categories = relationship("Category", back_populates="scan")

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    name = Column(String)
    score = Column(Float)
    vulnerability = Column(String)
    logs = Column(String) # שמירת "ראיות" (Chat Logs) כטקסט JSON
    scan = relationship("Scan", back_populates="categories")

# יצירת הטבלאות
Base.metadata.create_all(bind=engine_db)

# --- 3. סכימות לבקשות (Pydantic) ---
class AgentRequest(BaseModel):
    vulnerability: str
    brand_name: str

class StatusUpdate(BaseModel):
    status: str

# --- 4. אתחול אפליקציה וכלים ---
app = FastAPI(title="GEO-Pulse Ultimate API 2026")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# ייבוא המנוע של עובדת A
from engine import InsuranceGEOEngine

# משתנה גלובלי לניהול משימות בזיכרון
active_scans = {}
scheduler = BackgroundScheduler()

# --- 5. לוגיקת תזמון (Cron) ---
def run_automatic_scan():
    print(f"--- [CRON] סריקה אוטומטית החלה: {datetime.now()} ---")
    engine = InsuranceGEOEngine()
    db = SessionLocal()
    task_id = f"auto-{uuid.uuid4()}"
    
    new_scan = Scan(id=task_id, target_brand="ביטוח ישיר (אוטומטי)")
    db.add(new_scan)
    db.commit()

    config = {"CAT_AUTO": {"name": "ביטוח רכב", "focus": "סריקה תקופתית"}}
    score_accum = 0
    count = 0

    for step in engine.run_full_audit(config):
        if step.get("event") == "ZONE_COMPLETE":
            cat_data = step["data"]
            new_cat = Category(
                scan_id=task_id,
                name=cat_data["category"],
                score=float(cat_data.get("score_after", 0)),
                vulnerability=cat_data.get("vulnerability", ""),
                logs=json.dumps(cat_data.get("raw_chat_logs", []), ensure_ascii=False)
            )
            db.add(new_cat)
            score_accum += new_cat.score
            count += 1
            db.commit()

    if count > 0:
        new_scan.total_score = score_accum / count
        db.commit()
    
    db.close()
    print(f"--- [CRON] סריקה אוטומטית הושלמה ---")

@app.on_event("startup")
def start_scheduler():
    # מריץ פעם בשבוע
    scheduler.add_job(run_automatic_scan, 'interval', weeks=1)
    scheduler.start()

# --- 6. נתיבי ה-API (Endpoints) ---

@app.post("/api/v1/scans/dispatch")
async def start_scan(brand: str = "ביטוח ישיר"):
    task_id = str(uuid.uuid4())
    active_scans[task_id] = {"brand": brand}
    return {"taskId": task_id}

@app.get("/api/v1/scans/stream/{task_id}")
async def stream_scan(task_id: str):
    if task_id not in active_scans:
        raise HTTPException(status_code=404, detail="Task not found")
    
    brand = active_scans[task_id]["brand"]

    async def event_generator():
        engine = InsuranceGEOEngine()
        db = SessionLocal()
        
        new_scan = Scan(id=task_id, target_brand=brand)
        db.add(new_scan)
        db.commit()

        config = {"CAT_01": {"name": "ביטוח רכב", "focus": "אמינות ושירות"}}
        score_accum = 0
        cat_count = 0

        for step in engine.run_full_audit(config):
            # הזרמת הנתונים ל-Frontend
            yield f"data: {json.dumps(step, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.1)
            
            # שמירה ל-DB בסיום כל זירה
            if step.get("event") == "ZONE_COMPLETE":
                cat_data = step["data"]
                new_cat = Category(
                    scan_id=task_id,
                    name=cat_data["category"],
                    score=float(cat_data.get("score_after", 0)),
                    vulnerability=cat_data.get("vulnerability", ""),
                    logs=json.dumps(cat_data.get("raw_chat_logs", []), ensure_ascii=False)
                )
                db.add(new_cat)
                score_accum += new_cat.score
                cat_count += 1
                db.commit()

        # עדכון ציון סופי
        if cat_count > 0:
            new_scan.total_score = score_accum / cat_count
            db.commit()
            
        db.close()
        yield f"data: {json.dumps({'event': 'COMPLETE', 'data': {'scan_id': task_id, 'final_score': new_scan.total_score}}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/v1/history")
async def get_history():
    db = SessionLocal()
    scans = db.query(Scan).order_by(desc(Scan.date)).limit(5).all()
    output = [{"id": s.id, "brand": s.target_brand, "date": s.date.isoformat(), "score": s.total_score} for s in scans]
    db.close()
    return output

@app.get("/api/v1/analytics/compare/{scan_id}")
async def compare_scans(scan_id: str):
    db = SessionLocal()
    current = db.query(Scan).filter(Scan.id == scan_id).first()
    if not current:
        db.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    
    prev = db.query(Scan).filter(
        Scan.target_brand == current.target_brand, 
        Scan.date < current.date
    ).order_by(desc(Scan.date)).first()
    
    db.close()
    if not prev or prev.total_score == 0:
        return {"improvement_pct": 0, "message": "סריקה ראשונה או שאין נתונים להשוואה"}
    
    diff = current.total_score - prev.total_score
    pct = round((diff / prev.total_score) * 100, 2)
    return {"current_score": current.total_score, "previous_score": prev.total_score, "improvement_pct": pct}

@app.post("/api/v1/agent/write")
async def write_content(req: AgentRequest):
    if not client: return {"content": "OpenAI Key missing"}
    
    prompt = f"צור פוסט שיווקי חיובי ומתקן עבור המותג {req.brand_name}. הבעיה שזוהתה ב-AI היא: {req.vulnerability}"
    res = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    return {"suggested_content": res.choices[0].message.content}

@app.patch("/api/v1/recommendations/{category_id}/status")
async def update_status(category_id: int, req: StatusUpdate):
    db = SessionLocal()
    try:
        cat = db.query(Category).filter(Category.id == category_id).first()
        if not cat:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        
        # עדכון הסטטוס בתוך שדה ה-vulnerability (מניעת קריסה אם הוא None)
        old_val = cat.vulnerability if cat.vulnerability else ""
        cat.vulnerability = f"STATUS: {req.status} | {old_val}"
        
        db.commit()
        return {"status": "updated", "category_id": category_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()