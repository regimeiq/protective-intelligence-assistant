"""
Backtesting Framework — Golden Dataset Validation.

Compares the multi-factor scoring engine against a naive baseline using
8 known historical incidents. Validates that the full scoring model
(keyword weight x frequency factor x source credibility x recency)
outperforms simple keyword weight alone.

Baseline:  score = keyword_weight x 20 (no frequency, no credibility, no recency)
Full model: compute_risk_score() with simulated high-credibility source + spike + recency
"""

from analytics.risk_scoring import compute_risk_score, score_to_severity

# Golden dataset: known incidents with expected severity
# Each entry simulates a realistic scoring scenario
GOLDEN_DATASET = [
    {
        "name": "SolarWinds Supply Chain Attack",
        "keyword": "supply chain attack",
        "keyword_weight": 4.0,
        "expected_severity": "critical",
        "source_credibility": 1.0,  # CISA reported
        "frequency_factor": 3.5,  # Massive spike
        "recency_hours": 2.0,  # Very recent
        "description": "Nation-state supply chain compromise of SolarWinds Orion",
    },
    {
        "name": "Log4Shell (CVE-2021-44228)",
        "keyword": "remote code execution",
        "keyword_weight": 4.5,
        "expected_severity": "critical",
        "source_credibility": 1.0,
        "frequency_factor": 4.0,  # Extreme spike
        "recency_hours": 1.0,
        "description": "Critical RCE in Apache Log4j affecting millions of systems",
    },
    {
        "name": "MOVEit Transfer Exploitation (Cl0p)",
        "keyword": "zero day",
        "keyword_weight": 5.0,
        "expected_severity": "critical",
        "source_credibility": 0.85,
        "frequency_factor": 3.0,
        "recency_hours": 6.0,
        "description": "Mass exploitation of MOVEit file transfer zero-day by Cl0p",
    },
    {
        "name": "CrowdStrike Global Outage",
        "keyword": "exploitation",
        "keyword_weight": 3.5,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 2.0,
        "recency_hours": 6.0,
        "description": "Faulty CrowdStrike update causing widespread system failures",
    },
    {
        "name": "Colonial Pipeline Ransomware",
        "keyword": "ransomware",
        "keyword_weight": 4.5,
        "expected_severity": "critical",
        "source_credibility": 1.0,
        "frequency_factor": 3.0,
        "recency_hours": 4.0,
        "description": "DarkSide ransomware attack on critical infrastructure",
    },
    {
        "name": "Kaseya VSA Supply Chain",
        "keyword": "supply chain attack",
        "keyword_weight": 4.0,
        "expected_severity": "critical",
        "source_credibility": 0.85,
        "frequency_factor": 2.5,
        "recency_hours": 8.0,
        "description": "REvil ransomware via Kaseya VSA supply chain compromise",
    },
    {
        "name": "ProxyLogon (Exchange Server)",
        "keyword": "zero day",
        "keyword_weight": 5.0,
        "expected_severity": "critical",
        "source_credibility": 1.0,
        "frequency_factor": 3.5,
        "recency_hours": 12.0,
        "description": "Multiple Exchange Server zero-days exploited by Hafnium",
    },
    {
        "name": "PrintNightmare (CVE-2021-34527)",
        "keyword": "privilege escalation",
        "keyword_weight": 3.5,
        "expected_severity": "high",
        "source_credibility": 0.7,
        "frequency_factor": 1.5,
        "recency_hours": 18.0,
        "description": "Windows Print Spooler RCE/privilege escalation vulnerability",
    },
]


def run_backtest():
    """
    Run the full scoring model against the golden dataset and compare
    with baseline scoring.

    Returns:
        dict with per-incident results and aggregate metrics
    """
    results = []
    baseline_correct = 0
    full_correct = 0
    baseline_total_score = 0.0
    full_total_score = 0.0

    for incident in GOLDEN_DATASET:
        # Baseline: keyword_weight x 20, no other factors
        baseline_score = round(min(100.0, max(0.0, incident["keyword_weight"] * 20.0)), 1)
        baseline_severity = score_to_severity(baseline_score)

        # Full model: multi-factor scoring
        full_score, full_severity = compute_risk_score(
            keyword_weight=incident["keyword_weight"],
            source_credibility=incident["source_credibility"],
            frequency_factor=incident["frequency_factor"],
            recency_hours=incident["recency_hours"],
        )

        expected = incident["expected_severity"]
        baseline_match = baseline_severity == expected
        full_match = full_severity == expected

        if baseline_match:
            baseline_correct += 1
        if full_match:
            full_correct += 1

        baseline_total_score += baseline_score
        full_total_score += full_score

        results.append(
            {
                "incident": incident["name"],
                "keyword": incident["keyword"],
                "expected_severity": expected,
                "baseline_score": baseline_score,
                "baseline_severity": baseline_severity,
                "baseline_correct": baseline_match,
                "full_score": full_score,
                "full_severity": full_severity,
                "full_correct": full_match,
                "score_improvement": round(full_score - baseline_score, 1),
                "description": incident["description"],
            }
        )

    n = len(GOLDEN_DATASET)
    return {
        "incidents": results,
        "aggregate": {
            "total_incidents": n,
            "baseline_detection_rate": round(baseline_correct / n, 4),
            "full_detection_rate": round(full_correct / n, 4),
            "baseline_correct": baseline_correct,
            "full_correct": full_correct,
            "baseline_mean_score": round(baseline_total_score / n, 1),
            "full_mean_score": round(full_total_score / n, 1),
            "mean_score_improvement": round((full_total_score - baseline_total_score) / n, 1),
        },
    }
