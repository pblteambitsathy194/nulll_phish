"""
POST /api/v1/analyze-url
Accepts a URL, extracts 22 phishing features, runs the ML model, logs to MongoDB, returns verdict.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from services.feature_extractor import extract_all_features
from services.ml_model import predict_url
from services.visual_analyzer import analyze_visual_threat
from database.scan_log import log_scan_result
from database.db import get_database

router = APIRouter()


class UrlRequest(BaseModel):
    url: str


class FeatureScore(BaseModel):
    feature: str
    value: str
    score: int


class AnalysisResponse(BaseModel):
    url: str
    features: list[FeatureScore]
    total_score: int
    max_score: int
    risk_percentage: float
    verdict: str
    reason: str
    visual_risk_score: int


@router.post("/analyze-url", response_model=AnalysisResponse)
async def analyze_url(request: UrlRequest):
    """
    Analyze a URL for phishing indicators using the 22-feature checklist.
    Returns scores, verdict, and a risk percentage.
    """
    url = request.url

    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    try:
        # Step 0: Check Database Cache for "Instant" Crowdsourced Protection
        try:
            db = get_database()
            if db is not None:
                existing_threat = await db["scan_logs"].find_one(
                    {"url": url, "verdict": "🚨 PHISHING"},
                    sort=[("scanned_at", -1)]
                )
                if existing_threat:
                    return AnalysisResponse(
                        url=url,
                        features=[],  # Cached result doesn't need re-extraction
                        total_score=existing_threat["total_score"],
                        max_score=22,
                        risk_percentage=existing_threat["risk_percentage"],
                        verdict=existing_threat["verdict"],
                        reason="🚨 SHARED THREAT: This URL was previously flagged as malicious by our community intelligence system.",
                        visual_risk_score=existing_threat.get("visual_risk_score", 1)
                    )
        except Exception as e:
            print(f"⚠️ Database cache check failed: {e}. Falling back to ML analysis.")

        # Step 1: Extract all 22 features
        features = await extract_all_features(url)

        # Step 2: Run ML prediction
        prediction = predict_url(features)

        # Step 2.5: Visual Brand Analysis
        visual_risk_score = await analyze_visual_threat(url)

        # Step 3: Calculate scores
        total_score = sum(f["score"] for f in features)
        max_score = 22
        risk_percentage = round(((max_score - total_score) / (2 * max_score)) * 100, 1)

        # Step 4: Determine verdict
        if total_score > 5:
            verdict = "✅ LEGITIMATE"
            reason = "URL passes the majority of security checks. Domain reputation, SSL, and WHOIS data all appear legitimate."
        elif total_score >= 0:
            verdict = "⚠️ SUSPICIOUS"
            reason = "URL has some missing trust signals or exhibits minor suspicious characteristics. Proceed with caution."
        else:
            verdict = "🚨 PHISHING"
            reason = "URL exhibits multiple critical red flags typical of phishing or malicious intent. Do NOT proceed."

        # Override verdict if visual mimicking is detected
        if visual_risk_score == -1:
            verdict = "🚨 PHISHING"
            reason = "🚨 BRAND MIMICKING: This site claims to be a known brand but is hosted on a mismatching domain. High risk of credential theft."
            risk_percentage = max(risk_percentage, 95.0)

        # Step 5: Build response
        feature_scores = [
            FeatureScore(feature=f["feature"], value=f["value"], score=f["score"])
            for f in features
        ]

        response = AnalysisResponse(
            url=url,
            features=feature_scores,
            total_score=total_score,
            max_score=max_score,
            risk_percentage=risk_percentage,
            verdict=verdict,
            reason=reason,
            visual_risk_score=visual_risk_score
        )

        # Step 6: Log to database
        try:
            await log_scan_result(url, total_score, risk_percentage, verdict, prediction)
        except Exception as e:
            print(f"⚠️ Failed to log scan result to database: {e}")

        # Step 7: Push Notification if Malicious
        if verdict == "🚨 PHISHING":
            from database.device_token import get_all_device_tokens
            from services.fcm_service import send_malicious_url_alert
            tokens = await get_all_device_tokens()
            if tokens:
                await send_malicious_url_alert(tokens, url, risk_percentage, verdict)

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
