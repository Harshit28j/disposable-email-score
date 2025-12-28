from enum import Enum
from typing import Dict, List

from pydantic import BaseModel


class RiskLevel(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class RiskResult(BaseModel):
    decision: RiskLevel
    score: float
    thresholds: Dict[str, float]
    signals: Dict[str, float]
    reasons: List[str]
