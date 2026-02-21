import math
import random
from datetime import datetime, timedelta, timezone

from database.init_db import get_connection


def _percentile(sorted_values, q):
    if not sorted_values:
        return 0.0
    if q <= 0:
        return sorted_values[0]
    if q >= 1:
        return sorted_values[-1]
    idx = (len(sorted_values) - 1) * q
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return sorted_values[lower]
    weight = idx - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def _parse_timestamp(value):
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
    return max(0.1, 1.0 - (recency_hours / 168.0))


def score_distribution(
    keyword_weight,
    keyword_sigma,
    freq_factor,
    recency_factor,
    alpha,
    beta,
    n=500,
    seed=0,
):
    """
    Monte Carlo score distribution from Beta(source credibility) + Normal(keyword weight).
    Frequency and recency are deterministic in this mode.
    """
    if n <= 0:
        raise ValueError("n must be > 0")

    rng = random.Random(seed)
    safe_alpha = max(float(alpha or 0), 0.01)
    safe_beta = max(float(beta or 0), 0.01)
    safe_sigma = max(float(keyword_sigma or 0), 0.01)
    safe_weight = float(keyword_weight or 1.0)
    safe_freq = float(freq_factor or 1.0)
    safe_recency = float(recency_factor or 0.1)

    samples = []
    for _ in range(n):
        cred = rng.betavariate(safe_alpha, safe_beta)
        sampled_weight = min(5.0, max(0.1, rng.gauss(safe_weight, safe_sigma)))
        score = (sampled_weight * safe_freq * cred * 20.0) + (safe_recency * 10.0)
        samples.append(max(0.0, min(100.0, score)))

    samples.sort()
    mean = sum(samples) / len(samples)
    variance = sum((x - mean) ** 2 for x in samples) / len(samples)

    return {
        "n": n,
        "mean": round(mean, 3),
        "std": round(math.sqrt(variance), 3),
        "p05": round(_percentile(samples, 0.05), 3),
        "p50": round(_percentile(samples, 0.50), 3),
        "p95": round(_percentile(samples, 0.95), 3),
        "method": "monte_carlo_beta_normal_v1",
    }


def compute_uncertainty_for_alert(alert_id, n=500, seed=0, force=False, cache_hours=6):
    """Compute and cache uncertainty intervals in alert_score_intervals."""
    from analytics.risk_scoring import get_frequency_factor

    conn = get_connection()
    try:
        cached = conn.execute(
            "SELECT * FROM alert_score_intervals WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
        if cached and not force:
            computed_dt = _parse_timestamp(cached["computed_at"])
            is_fresh = computed_dt and (datetime.utcnow() - computed_dt) < timedelta(hours=cache_hours)
            if is_fresh and int(cached["n"]) == int(n):
                return dict(cached)

        row = conn.execute(
            """SELECT a.id, a.keyword_id, a.created_at, a.published_at,
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
            recency_factor = _compute_recency_factor(
                published_at=row["published_at"],
                created_at=row["created_at"],
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
