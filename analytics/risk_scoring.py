"""
Risk Scoring Engine for OSINT Threat Monitor.

Statistical approach:
- Z-score anomaly detection for keyword frequency spikes
- Bayesian credibility updating for source trustworthiness
- Multi-factor scoring with audit trail

Formula: risk_score = (keyword_weight * z_score_factor * bayesian_credibility * 20) + recency_bonus
Clamped to 0-100 range.

Severity derivation:
  90-100 = critical
  70-89  = high
  40-69  = medium
  0-39   = low
"""

import math
import random
from datetime import datetime, timedelta, timezone


def compute_risk_score(keyword_weight, source_credibility, frequency_factor, recency_hours):
    """
    Compute a 0-100 risk score and derive severity.

    Args:
        keyword_weight: Weight of the matched keyword (0.1-5.0)
        source_credibility: Bayesian credibility of the source (0.0-1.0)
        frequency_factor: Z-score-derived multiplier (1.0-4.0)
        recency_hours: Hours since the source event was published

    Returns:
        (risk_score, severity) tuple
    """
    recency_factor = max(0.1, 1.0 - (recency_hours / 168.0))
    raw_score = (keyword_weight * frequency_factor * source_credibility * 20.0) + (
        recency_factor * 10.0
    )
    risk_score = round(min(100.0, max(0.0, raw_score)), 1)
    severity = score_to_severity(risk_score)
    return risk_score, severity


def score_to_severity(score):
    """Map numeric score to severity label."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def get_keyword_weight(conn, keyword_id):
    """Fetch keyword weight from database, defaulting to 1.0."""
    row = conn.execute("SELECT weight FROM keywords WHERE id = ?", (keyword_id,)).fetchone()
    return row["weight"] if row and row["weight"] else 1.0


def get_source_credibility(conn, source_id):
    """
    Bayesian credibility using Beta distribution.
    credibility = alpha / (alpha + beta)
    Falls back to static credibility_score if no TP/FP data exists.
    """
    row = conn.execute(
        """SELECT credibility_score, bayesian_alpha, bayesian_beta,
                  true_positives, false_positives
           FROM sources WHERE id = ?""",
        (source_id,),
    ).fetchone()
    if not row:
        return 0.5

    alpha = row["bayesian_alpha"] if row["bayesian_alpha"] else 2.0
    beta = row["bayesian_beta"] if row["bayesian_beta"] else 2.0

    # If no TP/FP classifications yet, use static score
    if (row["true_positives"] or 0) == 0 and (row["false_positives"] or 0) == 0:
        return row["credibility_score"] if row["credibility_score"] else 0.5

    return round(alpha / (alpha + beta), 4)


def get_source_beta_params(conn, source_id):
    """Fetch source Bayesian alpha/beta with sane defaults."""
    row = conn.execute(
        "SELECT bayesian_alpha, bayesian_beta FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    if not row:
        return 2.0, 2.0
    alpha = float(row["bayesian_alpha"] or 2.0)
    beta = float(row["bayesian_beta"] or 2.0)
    return max(0.01, alpha), max(0.01, beta)


def get_frequency_factor(conn, keyword_id):
    """
    Z-score based frequency factor.
    z = (today_count - mean_7d) / std_dev_7d
    Maps z-score to a multiplier 1.0-4.0.
    Falls back to simple ratio when < 3 days of data.

    Returns:
        (frequency_factor, z_score) tuple
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    today_row = conn.execute(
        "SELECT count FROM keyword_frequency WHERE keyword_id = ? AND date = ?",
        (keyword_id, today),
    ).fetchone()
    today_count = today_row["count"] if today_row else 0

    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    rows = conn.execute(
        """SELECT count FROM keyword_frequency
        WHERE keyword_id = ? AND date >= ? AND date < ?""",
        (keyword_id, seven_days_ago, today),
    ).fetchall()

    counts = [row["count"] for row in rows]

    if len(counts) < 3:
        # Fallback to simple ratio for insufficient data
        avg = sum(counts) / len(counts) if counts else 1.0
        avg = max(avg, 1.0)
        ratio = today_count / avg
        return max(1.0, round(ratio, 2)), 0.0

    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    std_dev = variance**0.5

    if std_dev < 0.5:
        std_dev = 0.5  # Floor to prevent division-by-near-zero

    z_score = (today_count - mean) / std_dev

    # Map z-score to multiplier: 1.0 at z<=0, 4.0 at z>=4
    if z_score <= 0:
        factor = 1.0
    elif z_score >= 4.0:
        factor = 4.0
    else:
        factor = round(1.0 + (z_score * 0.75), 2)

    return factor, round(z_score, 2)


def build_frequency_snapshot(conn, keyword_ids=None):
    """Build a keyword -> (frequency_factor, z_score) snapshot for a scoring cycle."""
    if keyword_ids is None:
        rows = conn.execute("SELECT id FROM keywords WHERE active = 1").fetchall()
        keyword_ids = [row["id"] for row in rows]
    return {keyword_id: get_frequency_factor(conn, keyword_id) for keyword_id in keyword_ids}


def increment_keyword_frequency(conn, keyword_id, increment_by=1):
    """Increment today's frequency count for a keyword."""
    if increment_by <= 0:
        return
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn.execute(
        """INSERT INTO keyword_frequency (keyword_id, date, count)
        VALUES (?, ?, ?)
        ON CONFLICT(keyword_id, date)
        DO UPDATE SET count = count + excluded.count""",
        (keyword_id, today, increment_by),
    )


def _parse_timestamp(value):
    """Parse supported timestamp formats into a naive UTC datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    dt = None
            if dt is None:
                return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _compute_recency_factor(published_at=None, created_at=None):
    event_dt = _parse_timestamp(published_at) or _parse_timestamp(created_at) or datetime.utcnow()
    recency_hours = (datetime.utcnow() - event_dt).total_seconds() / 3600.0
    return max(0.1, 1.0 - (recency_hours / 168.0)), recency_hours


def _truncated_normal_sample(rng, mean, sd, lower, upper, max_attempts=20):
    """Sample from a normal distribution with truncation bounds."""
    safe_sd = max(float(sd), 0.001)
    for _ in range(max_attempts):
        value = rng.gauss(float(mean), safe_sd)
        if lower <= value <= upper:
            return value
    return min(upper, max(lower, value))


def _percentile(sorted_values, quantile):
    if not sorted_values:
        return 0.0
    if quantile <= 0:
        return sorted_values[0]
    if quantile >= 1:
        return sorted_values[-1]
    idx = (len(sorted_values) - 1) * quantile
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return sorted_values[lower]
    weight = idx - lower
    return (sorted_values[lower] * (1 - weight)) + (sorted_values[upper] * weight)


def simulate_risk_score(
    keyword_weight,
    frequency_factor,
    recency_factor,
    alpha,
    beta,
    n=500,
):
    """
    Monte Carlo uncertainty simulation for alert scoring.

    Samples:
      - keyword_weight ~ Normal(w, 0.15*w), truncated [0.1, 5.0]
      - source_credibility ~ Beta(alpha, beta)
      - frequency_factor ~ Normal(f, 0.20), truncated [1.0, 4.0]
      - recency_factor ~ Normal(r, 0.03), truncated [0.1, 1.0]
    """
    safe_n = max(100, int(n))
    rng = random.Random()
    samples = []
    base_weight = float(keyword_weight or 1.0)
    base_freq = float(frequency_factor or 1.0)
    base_recency = float(recency_factor or 0.1)
    safe_alpha = max(float(alpha or 0.01), 0.01)
    safe_beta = max(float(beta or 0.01), 0.01)

    for _ in range(safe_n):
        sampled_weight = _truncated_normal_sample(
            rng=rng,
            mean=base_weight,
            sd=max(0.05, 0.15 * base_weight),
            lower=0.1,
            upper=5.0,
        )
        sampled_credibility = rng.betavariate(safe_alpha, safe_beta)
        sampled_frequency = _truncated_normal_sample(
            rng=rng,
            mean=base_freq,
            sd=0.20,
            lower=1.0,
            upper=4.0,
        )
        sampled_recency_factor = _truncated_normal_sample(
            rng=rng,
            mean=base_recency,
            sd=0.03,
            lower=0.1,
            upper=1.0,
        )
        sampled_recency_hours = max(0.0, (1.0 - sampled_recency_factor) * 168.0)
        sampled_score, _ = compute_risk_score(
            keyword_weight=sampled_weight,
            source_credibility=sampled_credibility,
            frequency_factor=sampled_frequency,
            recency_hours=sampled_recency_hours,
        )
        samples.append(sampled_score)

    samples.sort()
    mean = sum(samples) / len(samples)
    variance = sum((score - mean) ** 2 for score in samples) / len(samples)
    std = math.sqrt(variance)

    return {
        "mean": round(mean, 3),
        "std": round(std, 3),
        "p05": round(_percentile(samples, 0.05), 3),
        "p50": round(_percentile(samples, 0.50), 3),
        "p95": round(_percentile(samples, 0.95), 3),
    }


def score_alert(
    conn,
    alert_id,
    keyword_id,
    source_id,
    created_at=None,
    published_at=None,
    frequency_override=None,
    z_score_override=None,
):
    """
    Full scoring pipeline for a single alert.
    Computes score, updates alert, and stores audit trail in alert_scores.
    Returns the final risk score.
    """
    keyword_weight = get_keyword_weight(conn, keyword_id)
    source_credibility = get_source_credibility(conn, source_id)
    if frequency_override is not None:
        frequency_factor = frequency_override
        z_score = z_score_override if z_score_override is not None else 0.0
    else:
        frequency_factor, z_score = get_frequency_factor(conn, keyword_id)

    recency_factor, recency_hours = _compute_recency_factor(
        published_at=published_at, created_at=created_at
    )

    risk_score, severity = compute_risk_score(
        keyword_weight, source_credibility, frequency_factor, recency_hours
    )
    source_alpha, source_beta = get_source_beta_params(conn, source_id)
    mc_stats = simulate_risk_score(
        keyword_weight=keyword_weight,
        frequency_factor=frequency_factor,
        recency_factor=recency_factor,
        alpha=source_alpha,
        beta=source_beta,
        n=500,
    )

    conn.execute(
        "UPDATE alerts SET risk_score = ?, severity = ? WHERE id = ?",
        (risk_score, severity, alert_id),
    )
    conn.execute(
        """INSERT INTO alert_scores
        (alert_id, keyword_weight, source_credibility, frequency_factor, z_score, recency_factor, final_score,
         mc_mean, mc_p05, mc_p50, mc_p95, mc_std)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert_id,
            keyword_weight,
            source_credibility,
            frequency_factor,
            z_score,
            recency_factor,
            risk_score,
            mc_stats["mean"],
            mc_stats["p05"],
            mc_stats["p50"],
            mc_stats["p95"],
            mc_stats["std"],
        ),
    )
    return risk_score


def compute_uncertainty_for_alert(alert_id, n=500, seed=0, force=False):
    """
    Compute (and cache) Monte Carlo uncertainty interval for one alert score.
    """
    from analytics.uncertainty import score_distribution
    from database.init_db import get_connection

    conn = get_connection()
    try:
        cached = conn.execute(
            "SELECT * FROM alert_score_intervals WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
        if cached and not force:
            computed_dt = _parse_timestamp(cached["computed_at"])
            cache_fresh = computed_dt and (datetime.utcnow() - computed_dt) < timedelta(hours=6)
            if cache_fresh and int(cached["n"]) == int(n):
                return dict(cached)

        row = conn.execute(
            """SELECT a.id, a.keyword_id, a.source_id, a.created_at, a.published_at,
                      k.weight, k.weight_sigma, s.bayesian_alpha, s.bayesian_beta
            FROM alerts a
            JOIN keywords k ON a.keyword_id = k.id
            JOIN sources s ON a.source_id = s.id
            WHERE a.id = ?""",
            (alert_id,),
        ).fetchone()
        if not row:
            raise ValueError("Alert not found")

        latest_score = conn.execute(
            """SELECT frequency_factor, recency_factor
            FROM alert_scores WHERE alert_id = ?
            ORDER BY computed_at DESC LIMIT 1""",
            (alert_id,),
        ).fetchone()
        if latest_score:
            freq_factor = latest_score["frequency_factor"]
            recency_factor = latest_score["recency_factor"]
        else:
            freq_factor, _ = get_frequency_factor(conn, row["keyword_id"])
            recency_factor, _ = _compute_recency_factor(
                published_at=row["published_at"], created_at=row["created_at"]
            )

        keyword_weight = row["weight"] if row["weight"] is not None else 1.0
        sigma_default = max(0.05, 0.2 * keyword_weight)
        keyword_sigma = row["weight_sigma"] if row["weight_sigma"] is not None else sigma_default
        alpha = row["bayesian_alpha"] if row["bayesian_alpha"] else 2.0
        beta = row["bayesian_beta"] if row["bayesian_beta"] else 2.0

        interval = score_distribution(
            keyword_weight=keyword_weight,
            keyword_sigma=keyword_sigma,
            freq_factor=freq_factor,
            recency_factor=recency_factor,
            alpha=alpha,
            beta=beta,
            n=n,
            seed=seed,
        )

        computed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO alert_score_intervals
            (alert_id, n, p05, p50, p95, mean, std, computed_at, method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                n = excluded.n,
                p05 = excluded.p05,
                p50 = excluded.p50,
                p95 = excluded.p95,
                mean = excluded.mean,
                std = excluded.std,
                computed_at = excluded.computed_at,
                method = excluded.method""",
            (
                alert_id,
                interval["n"],
                interval["p05"],
                interval["p50"],
                interval["p95"],
                interval["mean"],
                interval["std"],
                computed_at,
                interval["method"],
            ),
        )
        conn.commit()

        interval["computed_at"] = computed_at
        return interval
    finally:
        conn.close()


def rescore_all_alerts(conn):
    """
    Re-score all unreviewed alerts with current weights, Bayesian credibility,
    and Z-score frequency factors.
    Returns count of alerts rescored.
    """
    alerts = conn.execute(
        """SELECT a.id, a.keyword_id, a.source_id, a.created_at, a.published_at
        FROM alerts a WHERE a.reviewed = 0"""
    ).fetchall()
    count = 0
    for alert in alerts:
        score_alert(
            conn,
            alert["id"],
            alert["keyword_id"],
            alert["source_id"],
            created_at=alert["created_at"],
            published_at=alert["published_at"],
        )
        count += 1
    conn.commit()
    return count


def update_source_credibility_bayesian(conn, source_id, is_true_positive):
    """
    Update Bayesian credibility when an alert is classified as TP or FP.
    Uses Beta distribution: credibility = alpha / (alpha + beta).
    """
    if is_true_positive:
        conn.execute(
            """UPDATE sources SET
                true_positives = COALESCE(true_positives, 0) + 1,
                bayesian_alpha = COALESCE(bayesian_alpha, 2.0) + 1
            WHERE id = ?""",
            (source_id,),
        )
    else:
        conn.execute(
            """UPDATE sources SET
                false_positives = COALESCE(false_positives, 0) + 1,
                bayesian_beta = COALESCE(bayesian_beta, 2.0) + 1
            WHERE id = ?""",
            (source_id,),
        )
    # Sync the credibility_score column with Bayesian estimate
    row = conn.execute(
        "SELECT bayesian_alpha, bayesian_beta FROM sources WHERE id = ?",
        (source_id,),
    ).fetchone()
    if row:
        new_cred = row["bayesian_alpha"] / (row["bayesian_alpha"] + row["bayesian_beta"])
        conn.execute(
            "UPDATE sources SET credibility_score = ? WHERE id = ?",
            (round(new_cred, 4), source_id),
        )


def compute_evaluation_metrics(conn, source_id=None):
    """
    Compute precision, recall, and F1 for each source.
    Precision = TP / (TP + FP)
    Recall = TP / (TP + FN) where FN ~ reviewed but unclassified
    """
    if source_id is not None:
        source = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        sources = [source] if source else []
    else:
        sources = conn.execute("SELECT * FROM sources").fetchall()

    results = []
    for src in sources:
        tp = src["true_positives"] or 0
        fp = src["false_positives"] or 0
        reviewed_count = conn.execute(
            "SELECT COUNT(*) as count FROM alerts WHERE source_id = ? AND reviewed = 1",
            (src["id"],),
        ).fetchone()["count"]

        fn = max(0, reviewed_count - (tp + fp))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        alpha = src["bayesian_alpha"] or 2.0
        beta = src["bayesian_beta"] or 2.0

        results.append(
            {
                "source_id": src["id"],
                "source_name": src["name"],
                "true_positives": tp,
                "false_positives": fp,
                "total_reviewed": reviewed_count,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "bayesian_credibility": round(alpha / (alpha + beta), 4),
                "static_credibility": src["credibility_score"] or 0.5,
            }
        )

    return results
