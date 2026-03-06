"""
POST /api/v1/register-token
Endpoint for the Android app to register its FCM push token.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database.device_token import save_device_token

router = APIRouter()


class FcmTokenRequest(BaseModel):
    token: str
    device_id: str


class FcmTokenResponse(BaseModel):
    status: str
    message: str


@router.post("/register-token", response_model=FcmTokenResponse)
async def register_token(request: FcmTokenRequest):
    """
    Registers or updates the FCM push token for a specific device.
    This allows the backend to send malicious URL alerts via push notification.
    """
    if not request.token or not request.device_id:
        raise HTTPException(status_code=400, detail="token and device_id are required")

    try:
        await save_device_token(request.device_id, request.token)
        return FcmTokenResponse(status="success", message="Token registered successfully")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register token: {str(e)}")
