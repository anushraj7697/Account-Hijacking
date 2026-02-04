from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import cos, radians, sqrt
from typing import Dict

import numpy as np

from account_hijacking.models import FederatedRiskModel, UserProfile


@dataclass
class LoginAttempt:
    user_id: str
    ip_address: str
    latitude: float
    longitude: float
    device_id: str
    browser: str
    login_time: datetime


@dataclass
class RiskResult:
    risk_score: float
    features: Dict[str, float]


def _haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    earth_radius_km = 6371.0
    delta_lat = radians(lat2 - lat1)
    delta_lon = radians(lon2 - lon1)
    a = (
        (np.sin(delta_lat / 2) ** 2)
        + cos(radians(lat1)) * cos(radians(lat2)) * (np.sin(delta_lon / 2) ** 2)
    )
    c = 2 * np.arcsin(sqrt(a))
    return float(earth_radius_km * c)


def extract_features(attempt: LoginAttempt, profile: UserProfile) -> Dict[str, float]:
    ip_prefix = ".".join(attempt.ip_address.split(".")[:2])
    ip_mismatch = 0.0 if ip_prefix == profile.typical_ip_prefix else 1.0

    distance_km = _haversine_distance_km(
        profile.home_lat,
        profile.home_lon,
        attempt.latitude,
        attempt.longitude,
    )
    location_deviation = min(distance_km / 500.0, 1.0)

    device_unknown = 0.0 if attempt.device_id in profile.known_devices else 1.0
    browser_unknown = 0.0 if attempt.browser in profile.known_browsers else 1.0

    login_hour = attempt.login_time.hour + attempt.login_time.minute / 60.0
    time_deviation = min(abs(login_hour - profile.typical_login_hour) / 12.0, 1.0)

    return {
        "ip_mismatch": ip_mismatch,
        "location_deviation": location_deviation,
        "device_unknown": device_unknown,
        "browser_unknown": browser_unknown,
        "time_deviation": time_deviation,
    }


def score_risk(
    model: FederatedRiskModel,
    attempt: LoginAttempt,
    profile: UserProfile,
) -> RiskResult:
    features = extract_features(attempt, profile)
    feature_vector = np.array(list(features.values()), dtype=float)
    score = model.predict_proba(feature_vector)
    return RiskResult(risk_score=score, features=features)
