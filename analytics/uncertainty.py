import math
import random


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
