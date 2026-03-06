"""
Dashboard Router
Endpoints for serving the admin dashboard and providing live scan statistics.
"""

import os
from datetime import datetime, time, timezone
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from database.db import get_database
from urllib.parse import urlparse

router = APIRouter()

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

@router.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard_page():
    """Serve the dashboard HTML file."""
    html_path = os.path.join(TEMPLATES_DIR, "dashboard.html")
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="Dashboard template not found")
    
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()

@router.get("/api/v1/stats")
async def get_live_stats():
    """Calculate and return live statistics from MongoDB."""
    db = get_database()
    if db is None:
        return {
            "total_scanned": 0,
            "total_blocked": 0,
            "total_users": 0,
            "threats_today": 0,
            "risk_stats": {"legit": 0, "suspicious": 0, "phishing": 0},
            "top_domains": [],
            "last_scans": [],
            "warning": "Database connection unavailable. Showing empty stats."
        }

    # 1. Basic Counters
    total_scanned = await db["scan_logs"].count_documents({})
    total_blocked = await db["scan_logs"].count_documents({
        "$or": [
            {"verdict": "🚨 PHISHING"},
            {"risk_percentage": {"$gt": 80}}
        ]
    })
    total_users = await db["device_tokens"].count_documents({})

    # 2. Threats Today
    today_start = datetime.combine(datetime.now(timezone.utc).date(), time.min).replace(tzinfo=timezone.utc)
    threats_today = await db["scan_logs"].count_documents({
        "scanned_at": {"$gte": today_start},
        "$or": [
            {"verdict": "🚨 PHISHING"},
            {"risk_percentage": {"$gt": 80}}
        ]
    })

    # 3. Risk Distribution
    legit_count = await db["scan_logs"].count_documents({"verdict": "✅ LEGITIMATE"})
    phishing_count = await db["scan_logs"].count_documents({"verdict": "🚨 PHISHING"})
    total_logs = await db["scan_logs"].count_documents({})
    suspicious_count = total_logs - legit_count - phishing_count

    # 4. Top 10 Blocked Domains
    # In a production app, we'd use an aggregation pipeline. 
    # For now, let's fetch blocked logs and process in Python for simplicity.
    blocked_cursor = db["scan_logs"].find(
        {"$or": [{"verdict": "🚨 PHISHING"}, {"risk_percentage": {"$gt": 80}}]},
        {"url": 1}
    ).limit(1000)
    
    domain_counts = {}
    async for entry in blocked_cursor:
        try:
            domain = urlparse(entry["url"]).netloc
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except:
            continue
    
    top_domains = [
        {"domain": d, "count": c} 
        for d, c in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # 5. Last 20 Scans
    last_scans_cursor = db["scan_logs"].find({}).sort("scanned_at", -1).limit(20)
    last_scans = []
    async for scan in last_scans_cursor:
        last_scans.append({
            "time": scan["scanned_at"],
            "url": scan["url"],
            "risk": int(scan["risk_percentage"]),
            "verdict": scan["verdict"]
        })

    return {
        "total_scanned": total_scanned,
        "total_blocked": total_blocked,
        "total_users": total_users,
        "threats_today": threats_today,
        "risk_stats": {
            "legit": legit_count,
            "suspicious": max(0, suspicious_count),
            "phishing": phishing_count
        },
        "top_domains": top_domains,
        "last_scans": last_scans
    }
