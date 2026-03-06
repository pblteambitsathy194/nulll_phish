"""
POST /api/v1/report-phishing
Allows users to manually report a URL as malicious.
This updates the community database to protect all other users instantly.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database.scan_log import log_scan_result
from database.db import get_database

router = APIRouter()

class ReportRequest(BaseModel):
    url: str
    reason: str = "User Reported"

class ReportResponse(BaseModel):
    message: str
    url: str

@router.post("/report-phishing", response_model=ReportResponse)
async def report_phishing(request: ReportRequest):
    """
    Manually flag a URL as malicious.
    """
    url = request.url
    
    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    try:
        # Log this as a high-risk phishing result to trigger instant protection for others
        # We use a 100% risk score for user-confirmed reports
        await log_scan_result(
            url=url,
            total_score=-22, # Maximum red flags
            risk_percentage=100.0,
            verdict="🚨 PHISHING",
            prediction={"user_reported": True, "reason": request.reason}
        )

        # Trigger broadcast alert if needed (optional enhancement)
        # from services.fcm_service import send_malicious_url_alert
        # from database.device_token import get_all_device_tokens
        # ... logic to alert everyone immediately ...

        return ReportResponse(
            message="Thank you for your report. The community is now protected from this URL.",
            url=url
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process report: {str(e)}")
