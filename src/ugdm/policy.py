"""DecisionPolicyV1 and DecisionCostV1.

Research integrity rules encoded here:

* The policy is deterministic, versioned and documented.
* It only reads signals that are actually available at inference time. It never
  reads a ground-truth label, because the runtime does not have one.
* Risk and Action targets produced from this policy are labelled
  `POLICY_SUPERVISED`, never `HUMAN_GROUND_TRUTH`.
* Thresholds are selected on the Validation split by minimising expected cost.
  The frozen Test Set never participates in that selection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

POLICY_VERSION = "DecisionPolicyV1"
COST_VERSION = "DecisionCostV1"
TARGET_PROVENANCE = "POLICY_SUPERVISED"

RISK_CLASSES = ("SAFE", "SUSPICIOUS", "DANGEROUS")
ACTION_CLASSES = ("ALLOW", "REVIEW", "BLOCK")
THREAT_CLASSES = ("BENIGN", "PHISHING", "KNOWN_MALWARE", "OTHER")

RISK_TO_INDEX = {name: index for index, name in enumerate(RISK_CLASSES)}
ACTION_TO_INDEX = {name: index for index, name in enumerate(ACTION_CLASSES)}
THREAT_TO_INDEX = {name: index for index, name in enumerate(THREAT_CLASSES)}

RISK_SAFE, RISK_SUSPICIOUS, RISK_DANGEROUS = RISK_CLASSES
ACTION_ALLOW, ACTION_REVIEW, ACTION_BLOCK = ACTION_CLASSES


@dataclass(frozen=True)
class DecisionCost:
    """Normalized relative cost of each (true state, action) pair.

    These are explicit product research assumptions, not measured facts. The base
    unit is one benign review prompt. Ordering rationale:

    * Allowing known malware is the worst outcome (device compromise).
    * Allowing phishing is next (credential theft).
    * Reviewing a phishing URL is not a safe absorbing state: a warned user can
      still proceed, so it costs more than reviewing a benign URL.
    * Blocking a benign site is a serious usability failure, worse than asking.
    """

    version: str = COST_VERSION
    allow_benign: float = 0.0
    review_benign: float = 1.0
    block_benign: float = 20.0
    allow_phishing: float = 100.0
    review_phishing: float = 10.0
    block_phishing: float = 0.0
    allow_known_malware: float = 500.0
    review_known_malware: float = 25.0
    block_known_malware: float = 0.0

    def matrix(self) -> dict[str, dict[str, float]]:
        return {
            "BENIGN": {"ALLOW": self.allow_benign, "REVIEW": self.review_benign, "BLOCK": self.block_benign},
            "PHISHING": {
                "ALLOW": self.allow_phishing,
                "REVIEW": self.review_phishing,
                "BLOCK": self.block_phishing,
            },
            "KNOWN_MALWARE": {
                "ALLOW": self.allow_known_malware,
                "REVIEW": self.review_known_malware,
                "BLOCK": self.block_known_malware,
            },
        }

    def cost_of(self, true_state: str, action: str) -> float:
        return float(self.matrix()[true_state][action])

    def expected_cost(self, rows: list[tuple[str, str]]) -> float:
        """Mean cost over `(true_state, action)` pairs."""

        if not rows:
            return 0.0
        return float(sum(self.cost_of(state, action) for state, action in rows) / len(rows))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "unit": "one benign review prompt",
            "matrix": self.matrix(),
            "assumptions": (
                "Relative costs are product research assumptions, not objective measurements. "
                "They are versioned and must not be back-fitted from Test results."
            ),
        }


DEFAULT_COST = DecisionCost()

# Deployment prevalence assumption for the browser-assistant use case. The
# research splits are balanced at ~50% phishing, which is not what a deployed
# product sees; threshold selection must therefore use the deployment
# prevalence rather than the research prevalence. This is a documented product
# research assumption, versioned with the policy, and it is never fitted on Test.
DEPLOYMENT_PHISHING_PREVALENCE = 0.02


def prevalence_weights(
    labels: list[str],
    deployment_prevalence: float = DEPLOYMENT_PHISHING_PREVALENCE,
) -> list[float]:
    """Importance weights that reweight a balanced split to a deployment prevalence."""

    if not 0.0 < deployment_prevalence < 1.0:
        raise ValueError("deployment_prevalence must be within (0, 1)")
    if not labels:
        raise ValueError("labels must not be empty")
    observed = sum(1 for label in labels if label == "PHISHING") / len(labels)
    if observed <= 0.0 or observed >= 1.0:
        raise ValueError("both classes are required to compute prevalence weights")
    phishing_weight = deployment_prevalence / observed
    benign_weight = (1.0 - deployment_prevalence) / (1.0 - observed)
    return [phishing_weight if label == "PHISHING" else benign_weight for label in labels]


@dataclass(frozen=True)
class PolicyThresholds:
    """Probability thresholds used by DecisionPolicyV1."""

    review_at: float
    block_at: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.review_at <= 1.0:
            raise ValueError("review_at must be within [0, 1]")
        if not 0.0 <= self.block_at <= 1.0:
            raise ValueError("block_at must be within [0, 1]")
        if self.review_at > self.block_at:
            raise ValueError("review_at must not exceed block_at")

    def to_dict(self) -> dict[str, Any]:
        return {"reviewAt": self.review_at, "blockAt": self.block_at}


DEFAULT_THRESHOLDS = PolicyThresholds(review_at=0.30, block_at=0.70)

RISK_EVIDENCE_FEATURES = (
    "has_ip",
    "has_punycode",
    "has_at_symbol",
    "has_non_default_port",
    "contains_login",
    "contains_verify",
    "contains_secure",
    "contains_account",
    "contains_password",
    "contains_payment",
    "contains_wallet",
    "brand_domain_mismatch",
)


@dataclass(frozen=True)
class PolicyDecision:
    """One deterministic decision plus the evidence that produced it."""

    risk: str
    action: str
    reason: str
    phishing_probability: float
    risk_evidence_count: int
    known_malicious: bool
    whitelisted: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "action": self.action,
            "reason": self.reason,
            "phishingProbability": self.phishing_probability,
            "riskEvidenceCount": self.risk_evidence_count,
            "knownMalicious": self.known_malicious,
            "whitelisted": self.whitelisted,
            "policyVersion": POLICY_VERSION,
            "targetProvenance": TARGET_PROVENANCE,
        }


def risk_evidence_count(
    features: Mapping[str, float],
    availability: Mapping[str, bool],
) -> int:
    """Count risk indicators that are actually available for this row."""

    return sum(
        1
        for name in RISK_EVIDENCE_FEATURES
        if availability.get(name, False) and float(features.get(name, 0.0)) >= 0.5
    )


def decide(
    features: Mapping[str, float],
    availability: Mapping[str, bool],
    thresholds: PolicyThresholds = DEFAULT_THRESHOLDS,
) -> PolicyDecision:
    """Deterministic decision from runtime-available evidence only."""

    phishing_probability = float(features.get("phishing_probability", 0.0))
    known_malicious = bool(availability.get("known_malicious")) and float(
        features.get("known_malicious", 0.0)
    ) >= 0.5
    whitelisted = bool(availability.get("whitelist_hit")) and float(features.get("whitelist_hit", 0.0)) >= 0.5
    evidence = risk_evidence_count(features, availability)

    # 1. Confirmed intelligence evidence always wins. A whitelist entry must
    #    never override confirmed malicious evidence.
    if known_malicious:
        return PolicyDecision(
            risk=RISK_DANGEROUS,
            action=ACTION_BLOCK,
            reason="threat_intelligence_known_malicious",
            phishing_probability=phishing_probability,
            risk_evidence_count=evidence,
            known_malicious=True,
            whitelisted=whitelisted,
        )
    # 2. Strong benign evidence with no malicious evidence.
    if whitelisted:
        return PolicyDecision(
            risk=RISK_SAFE,
            action=ACTION_ALLOW,
            reason="local_whitelist_hit",
            phishing_probability=phishing_probability,
            risk_evidence_count=evidence,
            known_malicious=False,
            whitelisted=True,
        )
    # 3. High phishing probability plus at least one supporting risk signal.
    if phishing_probability >= thresholds.block_at and evidence >= 1:
        return PolicyDecision(
            risk=RISK_DANGEROUS,
            action=ACTION_BLOCK,
            reason="high_phishing_probability_with_supporting_evidence",
            phishing_probability=phishing_probability,
            risk_evidence_count=evidence,
            known_malicious=False,
            whitelisted=False,
        )
    # 4. Elevated phishing probability, or strong probability without support.
    if phishing_probability >= thresholds.review_at or (
        phishing_probability >= thresholds.block_at and evidence == 0
    ):
        return PolicyDecision(
            risk=RISK_SUSPICIOUS,
            action=ACTION_REVIEW,
            reason="elevated_phishing_probability",
            phishing_probability=phishing_probability,
            risk_evidence_count=evidence,
            known_malicious=False,
            whitelisted=False,
        )
    # 5. No meaningful evidence of risk.
    return PolicyDecision(
        risk=RISK_SAFE,
        action=ACTION_ALLOW,
        reason="low_probability_no_risk_evidence",
        phishing_probability=phishing_probability,
        risk_evidence_count=evidence,
        known_malicious=False,
        whitelisted=False,
    )


def select_thresholds(
    rows: list[dict[str, Any]],
    cost: DecisionCost = DEFAULT_COST,
    grid: tuple[float, ...] = (
        0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50,
        0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90,
    ),
    deployment_prevalence: float = DEPLOYMENT_PHISHING_PREVALENCE,
) -> dict[str, Any]:
    """Choose policy thresholds by minimising expected cost on the given rows.

    Costs are evaluated at the documented deployment prevalence, because a
    balanced research split would otherwise make "review everything" optimal and
    the selected thresholds useless in production. The caller must pass
    Validation rows only; selecting on Test would invalidate the frozen holdout.
    """

    weights = prevalence_weights([str(row["true_state"]) for row in rows], deployment_prevalence)
    best: tuple[float, PolicyThresholds] | None = None
    for review_at in grid:
        for block_at in grid:
            if review_at > block_at:
                continue
            thresholds = PolicyThresholds(review_at=review_at, block_at=block_at)
            total = 0.0
            weight_sum = 0.0
            for row, weight in zip(rows, weights):
                decision = decide(row["features"], row["availability"], thresholds)
                total += weight * cost.cost_of(str(row["true_state"]), decision.action)
                weight_sum += weight
            expected = total / weight_sum if weight_sum else 0.0
            if best is None or expected < best[0] - 1e-12:
                best = (expected, thresholds)
    if best is None:
        raise ValueError("No threshold candidate was evaluated")
    total, thresholds = best
    return {
        "thresholds": thresholds,
        "validationExpectedCost": total,
        "costVersion": cost.version,
        "policyVersion": POLICY_VERSION,
        "selectionSplit": "validation",
        "deploymentPrevalence": deployment_prevalence,
        "gridSize": len(grid) ** 2,
        "note": (
            "Thresholds minimise Validation expected cost under DecisionCostV1 at the documented "
            "deployment prevalence. The frozen Test Set is not used for this selection."
        ),
    }
