"""
URL Safety Analysis Backend - FastAPI Entry Point
Runs on port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.analyze import router as analyze_router
from routes.device_token import router as device_token_router
from routes.report import router as report_router
from routes.dashboard import router as dashboard_router
from routes.retrain import router as retrain_router
from database.db import connect_to_mongo, close_mongo_connection

app = FastAPI(
    title="URL Safety Analysis API",
    description="Backend for phishing URL detection using a 22-feature ML model",
    version="1.0.0"
)

# CORS - allow the Android app to communicate
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database lifecycle
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

# Routes
app.include_router(analyze_router, prefix="/api/v1", tags=["URL Analysis"])
app.include_router(device_token_router, prefix="/api/v1", tags=["Device Management"])
app.include_router(report_router, prefix="/api/v1", tags=["Phishing Reports"])
app.include_router(dashboard_router, tags=["Admin Dashboard"])
app.include_router(retrain_router, prefix="/api/v1", tags=["Model Training"])


@app.get("/", tags=["Health"])
async def health_check():
    return {"status": "ok", "message": "URL Safety Analysis API is running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
