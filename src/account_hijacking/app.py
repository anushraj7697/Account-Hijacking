from __future__ import annotations

from datetime import datetime
from typing import Dict

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from account_hijacking.adaptive import build_challenge, verify_challenge
from account_hijacking.models import FederatedRiskModel, UserProfile
from account_hijacking.risk import LoginAttempt, score_risk

app = FastAPI(title="Account Hijacking Prevention System")

FEATURE_COUNT = 5
RISK_THRESHOLD = 0.65

GLOBAL_MODEL = FederatedRiskModel(feature_count=FEATURE_COUNT)

USER_PROFILES: Dict[str, UserProfile] = {
    "alice": UserProfile(
        user_id="alice",
        typical_ip_prefix="192.168",
        home_lat=37.7749,
        home_lon=-122.4194,
        known_devices=["device-alice-1"],
        known_browsers=["Chrome", "Safari"],
        typical_login_hour=9.0,
        security_questions={
            "What city were you born in?": "San Francisco",
            "What is the name of your first pet?": "Mocha",
        },
    ),
    "bob": UserProfile(
        user_id="bob",
        typical_ip_prefix="10.0",
        home_lat=40.7128,
        home_lon=-74.0060,
        known_devices=["device-bob-1"],
        known_browsers=["Firefox"],
        typical_login_hour=20.0,
        security_questions={
            "What is your favorite book?": "Dune",
            "What city did you meet your spouse?": "Boston",
        },
    ),
}


class LoginRequest(BaseModel):
    user_id: str
    ip_address: str
    latitude: float
    longitude: float
    device_id: str
    browser: str
    login_time: datetime = Field(default_factory=datetime.utcnow)
    answers: Dict[str, str] | None = None


class LoginResponse(BaseModel):
    decision: str
    risk_score: float
    features: Dict[str, float]
    challenge: Dict[str, str] | None = None
    adaptive_score: float | None = None


@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest) -> LoginResponse:
    profile = USER_PROFILES.get(request.user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Unknown user")

    attempt = LoginAttempt(
        user_id=request.user_id,
        ip_address=request.ip_address,
        latitude=request.latitude,
        longitude=request.longitude,
        device_id=request.device_id,
        browser=request.browser,
        login_time=request.login_time,
    )

    risk_result = score_risk(GLOBAL_MODEL, attempt, profile)

    if risk_result.risk_score < RISK_THRESHOLD:
        return LoginResponse(
            decision="allow",
            risk_score=risk_result.risk_score,
            features=risk_result.features,
        )

    challenge = build_challenge(profile)

    if not request.answers:
        return LoginResponse(
            decision="challenge",
            risk_score=risk_result.risk_score,
            features=risk_result.features,
            challenge={"questions": ", ".join(challenge.questions)},
        )

    adaptive_result = verify_challenge(profile, request.answers)
    if adaptive_result.success:
        return LoginResponse(
            decision="allow",
            risk_score=risk_result.risk_score,
            features=risk_result.features,
            adaptive_score=adaptive_result.score,
        )

    return LoginResponse(
        decision="block",
        risk_score=risk_result.risk_score,
        features=risk_result.features,
        adaptive_score=adaptive_result.score,
    )


class FederatedUpdateRequest(BaseModel):
    user_id: str
    features: Dict[str, float]
    label: float


@app.post("/federated/update")
async def federated_update(request: FederatedUpdateRequest) -> Dict[str, str]:
    if request.user_id not in USER_PROFILES:
        raise HTTPException(status_code=404, detail="Unknown user")

    feature_vector = list(request.features.values())
    if len(feature_vector) != FEATURE_COUNT:
        raise HTTPException(status_code=400, detail="Invalid feature count")

    local_model = FederatedRiskModel(feature_count=FEATURE_COUNT)
    local_model.weights = GLOBAL_MODEL.weights.copy()
    local_model.bias = GLOBAL_MODEL.bias
    local_model.local_update(
        features=np.array(feature_vector, dtype=float),
        label=request.label,
    )
    GLOBAL_MODEL.federated_average([local_model])
    return {"status": "updated"}
