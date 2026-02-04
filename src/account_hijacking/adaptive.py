from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from account_hijacking.models import UserProfile


@dataclass
class AdaptiveChallenge:
    questions: List[str]


@dataclass
class AdaptiveResult:
    success: bool
    score: float


def build_challenge(profile: UserProfile, max_questions: int = 2) -> AdaptiveChallenge:
    questions = list(profile.security_questions.keys())[:max_questions]
    return AdaptiveChallenge(questions=questions)


def verify_challenge(profile: UserProfile, answers: Dict[str, str]) -> AdaptiveResult:
    if not answers:
        return AdaptiveResult(success=False, score=0.0)

    total = 0
    correct = 0
    for question, expected in profile.security_questions.items():
        if question in answers:
            total += 1
            if answers[question].strip().lower() == expected.strip().lower():
                correct += 1
    score = correct / total if total else 0.0
    return AdaptiveResult(success=score >= 0.7, score=score)
