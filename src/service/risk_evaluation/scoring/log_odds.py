"""Log-Odds Bayesian risk scoring.

An alternative to the weight-based risk-level scoring. Instead of averaging per-parameter
partial risk levels, every signal contributes an *evidence* term (in log-odds space) that is
summed together with a calibratable *bias* and passed through a logistic function:

    P(fraud) = 1 / (1 + exp(-(evidence + bias)))

The resulting continuous probability in ``[0, 1]`` is then mapped to a discrete risk level
(1..4) via configurable thresholds.

Evidence convention (per signal, clamped to roughly [-2.5, +2.5]):
    * positive  -> risk signal   (a changed / anomalous parameter raises risk)
    * negative  -> trust signal  (a stable identity parameter lowers risk)

The bias term calibrates the model to a deployment's base fraud rate. Lower (more
negative) bias means the system is more trusting; higher bias means more suspicious.

    Industry (fraud rate)     Suggested bias
    Public Services (0.1%)    -6.9
    E-commerce (1-2%)         -4.6 .. -3.9
    Financial (2-5%)          -3.9 .. -2.9
    High-Security (10%)       -2.2

This module has no I/O and no framework dependencies: it consumes already-computed
signals and returns a decision, which keeps it trivial to unit test and reason about.
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, Any, Iterable, List


# Maximum magnitude of a single signal's evidence contribution (log-odds units).
# A weight-3 parameter that changed contributes the full +MAX_RISK_EVIDENCE.
MAX_RISK_EVIDENCE = 2.5

# Magnitude of the trust (negative) evidence a stable identity parameter contributes.
# Deliberately smaller than the risk evidence: a single stable signal should nudge,
# not dominate, whereas a single anomalous signal should weigh heavily.
MAX_TRUST_EVIDENCE = 0.5

# Scale applied to the credibility composite. Credibility is in [0, 1] centred at 0.5,
# so (0.5 - c) is in [-0.5, +0.5]; multiplying by 5.0 maps it to [-2.5, +2.5].
CREDIBILITY_SCALE = 5.0

# Weight used to combine device and network-location credibility, mirroring the
# weight-based path so both scoring modes treat credibility identically.
DEVICE_CREDIBILITY_WEIGHT = 0.55
NET_LOC_CREDIBILITY_WEIGHT = 0.45

# Identity / fingerprint parameters. When one of these is enabled and did NOT change,
# it is treated as a trust signal (mild negative evidence). Behavioural anomaly flags
# (impossible_travel, anonymous_detection, date_time, ...) are excluded: their absence
# is the norm rather than positive evidence of trust.
IDENTITY_PARAMS = frozenset(
    {
        "client",
        "ip_address",
        "device",
        "operating_system",
        "browser",
        "system_language",
        "screen_resolution",
        "geolocation_cluster_label",
    }
)

DEFAULT_RISK_THRESHOLDS = (0.30, 0.60, 0.85)


@dataclass
class LogOddsResult:
    """Outcome of a single Log-Odds scoring pass, useful for logging and tests."""

    risk_level: int
    probability: float
    evidence: float
    bias: float
    contributions: Dict[str, float] = field(default_factory=dict)


class LogOddsScorer:
    """Computes a risk-level decision from accumulated log-odds evidence.

    Args:
        decision_params:
            The active per-realm/group parameter configuration, as returned by
            ``DecisionParamsFactory`` (parameter name -> {"weight", "enabled", ...}).
            The ``__meta`` key, if present, is ignored.
        bias:
            Calibration term added to the summed evidence before the logistic.
        thresholds:
            Three ascending probabilities ``(t1, t2, t3)`` partitioning ``[0, 1]`` into
            risk-level bands: ``p < t1 -> 1``, ``t1 <= p < t2 -> 2``, ``t2 <= p < t3 -> 3``,
            ``p >= t3 -> 4``.
    """

    def __init__(
        self,
        decision_params: Dict[str, Dict[str, Any]],
        bias: float,
        thresholds: tuple = DEFAULT_RISK_THRESHOLDS,
    ) -> None:
        self.decision_params = decision_params or {}
        self.bias = float(bias)
        self.thresholds = self._validate_thresholds(thresholds)

    @staticmethod
    def _validate_thresholds(thresholds) -> tuple:
        try:
            t1, t2, t3 = (float(t) for t in thresholds)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"thresholds must be three numbers, got {thresholds!r}"
            ) from exc
        if not (0.0 <= t1 < t2 < t3 <= 1.0):
            raise ValueError(
                f"thresholds must be ascending within [0, 1], got {(t1, t2, t3)}"
            )
        return (t1, t2, t3)

    def _enabled_params(self) -> List[str]:
        return [
            name
            for name, conf in self.decision_params.items()
            if name != "__meta" and conf.get("enabled", True)
        ]

    def _weight_factor(self, param: str) -> float:
        """Scale a signal's evidence by its configured weight (1..3+ -> ~0.33..1.0)."""
        weight = self.decision_params.get(param, {}).get("weight", 3)
        return min(weight, 3) / 3.0

    def score(
        self,
        changed_vars: List[str],
        device_credibility: float,
        net_loc_credibility: float,
        unavailable_vars: Iterable[str] = (),
    ) -> LogOddsResult:
        """Run the Log-Odds model.

        Args:
            changed_vars:
                Parameters considered changed/anomalous for this event (the same list
                the weight-based path derives from short-term detection).
            device_credibility:
                Device trust score in ``[0, 1]`` (higher is more trusted).
            net_loc_credibility:
                Network-location trust score in ``[0, 1]``.
            unavailable_vars:
                Parameters this login could not be compared on (a missing screen
                resolution, for example). They add neither risk nor trust.

        Returns:
            LogOddsResult: the risk level plus the probability and evidence breakdown.
        """
        changed = set(changed_vars or [])
        unavailable = set(unavailable_vars or ())
        contributions: Dict[str, float] = {}

        for param in self._enabled_params():
            if param in unavailable:
                continue
            factor = self._weight_factor(param)
            if param in changed:
                contributions[param] = MAX_RISK_EVIDENCE * factor
            elif param in IDENTITY_PARAMS:
                contributions[param] = -MAX_TRUST_EVIDENCE * factor

        # Any anomaly flag that changed but is not a configured parameter at all (e.g.
        # flags surfaced purely by EvalRisk) still contributes full-weight risk evidence.
        # Configured-but-disabled parameters are intentionally left out above and must
        # not be resurrected here.
        for param in changed:
            if param not in contributions and param not in self.decision_params:
                contributions[param] = MAX_RISK_EVIDENCE * self._weight_factor(param)

        composite_credibility = (
            device_credibility * DEVICE_CREDIBILITY_WEIGHT
            + net_loc_credibility * NET_LOC_CREDIBILITY_WEIGHT
        )
        contributions["__credibility"] = (
            0.5 - composite_credibility
        ) * CREDIBILITY_SCALE

        evidence = sum(contributions.values())
        probability = self._logistic(evidence + self.bias)
        risk_level = self._probability_to_risk_level(probability)

        logging.debug(
            "Log-Odds scoring: evidence=%.4f bias=%.4f p(fraud)=%.4f -> Risk %d "
            "contributions=%s",
            evidence,
            self.bias,
            probability,
            risk_level,
            contributions,
        )

        return LogOddsResult(
            risk_level=risk_level,
            probability=probability,
            evidence=evidence,
            bias=self.bias,
            contributions=contributions,
        )

    @staticmethod
    def _logistic(x: float) -> float:
        # Guard against overflow for large-magnitude evidence.
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        z = math.exp(x)
        return z / (1.0 + z)

    def _probability_to_risk_level(self, probability: float) -> int:
        t1, t2, t3 = self.thresholds
        if probability < t1:
            return 1
        if probability < t2:
            return 2
        if probability < t3:
            return 3
        return 4
