from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import numpy as np


@dataclass
class UserProfile:
    user_id: str
    typical_ip_prefix: str
    home_lat: float
    home_lon: float
    known_devices: List[str]
    known_browsers: List[str]
    typical_login_hour: float
    security_questions: Dict[str, str]


class FederatedRiskModel:
    def __init__(self, feature_count: int, learning_rate: float = 0.1) -> None:
        self.feature_count = feature_count
        self.learning_rate = learning_rate
        self.weights = np.zeros(feature_count, dtype=float)
        self.bias = 0.0

    def predict_proba(self, features: np.ndarray) -> float:
        logits = float(np.dot(self.weights, features) + self.bias)
        return float(1 / (1 + np.exp(-logits)))

    def local_update(self, features: np.ndarray, label: float) -> None:
        prediction = self.predict_proba(features)
        error = prediction - label
        self.weights -= self.learning_rate * error * features
        self.bias -= self.learning_rate * error

    def federated_average(self, client_updates: List["FederatedRiskModel"]) -> None:
        if not client_updates:
            return
        weights_stack = np.stack([client.weights for client in client_updates])
        biases = np.array([client.bias for client in client_updates], dtype=float)
        self.weights = np.mean(weights_stack, axis=0)
        self.bias = float(np.mean(biases))
