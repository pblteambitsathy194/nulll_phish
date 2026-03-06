"""
Retrain Router
Endpoint for retraining the Random Forest model using confirmed phishing reports.
"""

import os
import joblib
import numpy as np
from fastapi import APIRouter, HTTPException
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from database.db import get_database
from services.feature_extractor import extract_all_features

router = APIRouter()

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

@router.post("/retrain")
async def retrain_model():
    """
    Fetch confirmed reports, re-extract features, and update the Random Forest model.
    """
    db = get_database()
    if db is None:
        return {
            "status": "error",
            "message": "Model retraining unavailable. No active MongoDB connection."
        }

    # 1. Fetch confirmed reports (those marked as PHISHING in scan_logs)
    cursor = db["scan_logs"].find({"verdict": "🚨 PHISHING"}).limit(500)
    confirmed_urls = []
    async for doc in cursor:
        confirmed_urls.append(doc["url"])

    # Also fetch some legitimate samples to balance the dataset
    # In a real app, you would have a 'whitelist' or verified legit collection
    legit_cursor = db["scan_logs"].find({"verdict": "✅ LEGITIMATE"}).limit(len(confirmed_urls) + 50)
    legit_urls = []
    async for doc in legit_cursor:
        legit_urls.append(doc["url"])

    if not confirmed_urls:
        return {"status": "skipped", "message": "Not enough phishing reports to retrain."}

    X = []
    y = []

    print(f"🔄 Retraining with {len(confirmed_urls)} phishing and {len(legit_urls)} legit samples...")

    # 2. Extract features for training data
    # (Note: In production, you'd store features in the DB to avoid re-extraction)
    for url in confirmed_urls:
        try:
            feats = await extract_all_features(url)
            X.append([f["score"] for f in feats])
            y.append(0) # Phishing
        except:
            continue

    for url in legit_urls:
        try:
            feats = await extract_all_features(url)
            X.append([f["score"] for f in feats])
            y.append(1) # Legitimate
        except:
            continue

    if len(X) < 10:
        raise HTTPException(status_code=400, detail="Insufficient feature data extracted for retraining.")

    # 3. Retrain
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    accuracy = clf.score(X_test, y_test)

    # 4. Save to Backend/models/
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    joblib.dump(clf, MODEL_PATH)

    return {
        "status": "success",
        "accuracy": round(accuracy, 4),
        "samples_used": len(X),
        "model_path": MODEL_PATH
    }
