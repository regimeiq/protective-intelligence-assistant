from datetime import datetime, timedelta

from analytics.utils import utcnow
from database.init_db import get_connection


def _smape(actuals, forecasts):
    values = []
    for actual, forecast in zip(actuals, forecasts):
        denom = (abs(actual) + abs(forecast)) / 2.0
        if denom == 0:
            continue
        values.append(abs(actual - forecast) / denom)
    if not values:
        return None
    return round(100 * (sum(values) / len(values)), 3)


def _dense_series(rows):
    if not rows:
        return []

    counts = {row["date"]: row["count"] for row in rows}
    start = datetime.strptime(rows[0]["date"], "%Y-%m-%d")
    end = datetime.strptime(rows[-1]["date"], "%Y-%m-%d")

    dense = []
    cursor = start
    while cursor <= end:
        day = cursor.strftime("%Y-%m-%d")
        dense.append({"date": day, "count": counts.get(day, 0)})
        cursor += timedelta(days=1)
    return dense


def _ewma_with_trend(values, horizon):
    alpha = 0.35
    level = values[0]
    level_series = [level]
    for value in values[1:]:
        level = alpha * value + (1 - alpha) * level
        level_series.append(level)

    n = len(level_series)
    x_values = list(range(n))
    x_mean = sum(x_values) / n
    y_mean = sum(level_series) / n
    numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, level_series))
    denominator = sum((x - x_mean) ** 2 for x in x_values) or 1.0
    slope = numerator / denominator
    intercept = y_mean - slope * x_mean

    fitted = [intercept + slope * x for x in x_values]
    residuals = [actual - fit for actual, fit in zip(values, fitted)]
    sigma = (sum((r**2) for r in residuals) / len(residuals)) ** 0.5 if residuals else 1.0
    sigma = max(sigma, 1.0)

    predictions = []
    for step in range(1, horizon + 1):
        idx = n - 1 + step
        yhat = max(0.0, intercept + slope * idx)
        margin = 1.96 * sigma * (step**0.5)
        predictions.append(
            {
                "step": step,
                "yhat": round(yhat, 3),
                "lo": round(max(0.0, yhat - margin), 3),
                "hi": round(max(0.0, yhat + margin), 3),
            }
        )
    return predictions


def _naive_forecast(last_value, horizon):
    base = max(0.0, float(last_value))
    spread = max(2.0, base * 0.75)
    return [
        {
            "step": step,
            "yhat": round(base, 3),
            "lo": round(max(0.0, base - spread), 3),
            "hi": round(base + spread, 3),
        }
        for step in range(1, horizon + 1)
    ]


def forecast_keyword(keyword_id, horizon=7):
    """
    Forecast next N days of keyword frequency.
    Uses EWMA+trend when enough data; otherwise falls back to naive last value.
    """
    safe_horizon = max(1, min(int(horizon), 30))
    conn = get_connection()
    rows = conn.execute(
        """SELECT date, count FROM keyword_frequency
        WHERE keyword_id = ?
        ORDER BY date ASC""",
        (keyword_id,),
    ).fetchall()
    conn.close()

    dense = _dense_series(rows)
    history = dense[-30:]

    if not dense:
        today = utcnow()
        forecast = []
        for step, point in enumerate(_naive_forecast(0, safe_horizon), start=1):
            forecast_date = (today + timedelta(days=step)).strftime("%Y-%m-%d")
            forecast.append({"date": forecast_date, **point, "method": "naive_last_value"})
        return {
            "keyword_id": keyword_id,
            "method": "naive_last_value",
            "forecast": forecast,
            "quality": {"smape": None, "n_train_days": 0},
            "history": history,
        }

    values = [row["count"] for row in dense]
    last_date = datetime.strptime(dense[-1]["date"], "%Y-%m-%d")

    if len(values) < 14:
        raw_forecast = _naive_forecast(values[-1], safe_horizon)
        method = "naive_last_value"
        quality = {"smape": None, "n_train_days": len(values)}
    else:
        raw_forecast = _ewma_with_trend(values, safe_horizon)
        method = "ewma_trend"
        quality = {"smape": None, "n_train_days": len(values)}
        if len(values) >= 21:
            train = values[:-7]
            test = values[-7:]
            test_forecast = _ewma_with_trend(train, 7)
            quality = {
                "smape": _smape(test, [point["yhat"] for point in test_forecast]),
                "n_train_days": len(train),
            }

    forecast = []
    for point in raw_forecast:
        forecast_date = (last_date + timedelta(days=point["step"])).strftime("%Y-%m-%d")
        forecast.append(
            {
                "date": forecast_date,
                "yhat": point["yhat"],
                "lo": point["lo"],
                "hi": point["hi"],
                "method": method,
            }
        )

    return {
        "keyword_id": keyword_id,
        "method": method,
        "forecast": forecast,
        "quality": quality,
        "history": history,
    }
