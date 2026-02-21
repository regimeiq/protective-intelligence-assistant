import os
from datetime import date, datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("OSINT_API_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(
    page_title="OSINT Threat Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ OSINT Threat Monitor — Protective Intelligence Platform")

# --- Check API connection ---
try:
    requests.get(f"{API_URL}/", timeout=3)
except requests.ConnectionError:
    st.error("Cannot connect to API. Make sure the API server is running on port 8000.")
    st.stop()

# --- Tab layout ---
(
    tab_overview,
    tab_intel,
    tab_alerts,
    tab_analytics,
    tab_forecast,
    tab_graph,
    tab_scoring,
    tab_perf,
    tab_config,
) = st.tabs(
    [
        "📊 Overview",
        "📋 Intelligence Report",
        "🚨 Alert Feed",
        "📈 Analytics",
        "🔮 Forecast",
        "🕸️ Graph",
        "🧮 Scoring & Evaluation",
        "⚡ Performance",
        "⚙️ Configuration",
    ]
)

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}
SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


# ============================================================
# TAB 1: OVERVIEW
# ============================================================
with tab_overview:
    try:
        summary = requests.get(f"{API_URL}/alerts/summary").json()

        # KPI Row
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        col1.metric("Total Alerts", summary["total_alerts"])
        col2.metric("Unique Alerts", summary.get("unique_alerts", summary["total_alerts"]))
        col3.metric("Critical", summary["by_severity"].get("critical", 0))
        col4.metric("High", summary["by_severity"].get("high", 0))
        col5.metric("Avg Risk Score", f"{summary.get('avg_risk_score', 0):.1f}")
        col6.metric("Active Spikes", summary.get("active_spikes", 0))

        # Second KPI row
        col7, col8, col9 = st.columns(3)
        col7.metric("Unreviewed", summary["unreviewed"])
        col8.metric("Duplicates Detected", summary.get("duplicates", 0))
        dedup_pct = (
            round(summary.get("duplicates", 0) / summary["total_alerts"] * 100, 1)
            if summary["total_alerts"] > 0
            else 0
        )
        col9.metric("Dedup Rate", f"{dedup_pct}%")

        st.divider()

        # Charts row
        col_left, col_mid, col_right = st.columns(3)

        with col_left:
            st.subheader("Alerts by Severity")
            if summary["by_severity"]:
                severity_df = pd.DataFrame(
                    list(summary["by_severity"].items()), columns=["Severity", "Count"]
                )
                severity_order = ["critical", "high", "medium", "low"]
                severity_df["Severity"] = pd.Categorical(
                    severity_df["Severity"], categories=severity_order, ordered=True
                )
                severity_df = severity_df.sort_values("Severity")
                fig_sev = px.bar(
                    severity_df,
                    x="Severity",
                    y="Count",
                    color="Severity",
                    color_discrete_map=SEVERITY_COLORS,
                )
                fig_sev.update_layout(showlegend=False, height=350)
                st.plotly_chart(fig_sev, use_container_width=True)

        with col_mid:
            st.subheader("Alerts by Source")
            if summary["by_source"]:
                source_df = pd.DataFrame(
                    list(summary["by_source"].items()), columns=["Source", "Count"]
                )
                fig_src = px.pie(source_df, values="Count", names="Source", hole=0.4)
                fig_src.update_layout(height=350)
                st.plotly_chart(fig_src, use_container_width=True)

        with col_right:
            st.subheader("Top Matched Keywords")
            if summary["top_keywords"]:
                kw_df = pd.DataFrame(
                    list(summary["top_keywords"].items()), columns=["Keyword", "Count"]
                )
                kw_df = kw_df.sort_values("Count", ascending=True)
                fig_kw = px.bar(kw_df, x="Count", y="Keyword", orientation="h")
                fig_kw.update_layout(height=350)
                st.plotly_chart(fig_kw, use_container_width=True)

        # Risk score distribution
        st.subheader("Risk Score Distribution")
        alerts_for_dist = requests.get(f"{API_URL}/alerts", params={"limit": 500}).json()
        if alerts_for_dist:
            scores = [a["risk_score"] for a in alerts_for_dist if a.get("risk_score")]
            if scores:
                fig_hist = px.histogram(
                    x=scores,
                    nbins=20,
                    labels={"x": "Risk Score", "y": "Count"},
                    color_discrete_sequence=["#f97316"],
                )
                fig_hist.update_layout(
                    xaxis_title="Risk Score",
                    yaxis_title="Alert Count",
                    height=300,
                )
                st.plotly_chart(fig_hist, use_container_width=True)

    except requests.ConnectionError:
        st.error("Cannot connect to API.")


# ============================================================
# TAB 2: INTELLIGENCE REPORT
# ============================================================
with tab_intel:
    st.subheader("Daily Intelligence Report")

    report_date = st.date_input("Report Date", value=date.today())

    try:
        report = requests.get(
            f"{API_URL}/intelligence/daily",
            params={"date": report_date.strftime("%Y-%m-%d")},
        ).json()

        # Executive Summary
        st.markdown("### Executive Summary")
        st.info(report.get("executive_summary", "No data available for this date."))

        # Stats row
        stats = report.get("stats", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total", stats.get("total_alerts", 0))
        c2.metric("Critical", stats.get("critical_count", 0))
        c3.metric("High", stats.get("high_count", 0))
        c4.metric("Medium", stats.get("medium_count", 0))

        st.divider()

        # Escalation Recommendations
        escalations = report.get("escalation_recommendations", [])
        st.markdown("### Escalation Recommendations")
        if escalations:
            for esc in escalations:
                priority = esc.get("priority", "MEDIUM")
                if priority == "IMMEDIATE":
                    st.error(f"**[{priority}]** {esc.get('action', '')}")
                elif priority == "HIGH":
                    st.warning(f"**[{priority}]** {esc.get('action', '')}")
                else:
                    st.info(f"**[{priority}]** {esc.get('action', '')}")
        else:
            st.success("No escalation items at this time.")

        st.divider()

        # Top Risks
        top_risks = report.get("top_risks", [])
        st.markdown("### Top Risks")
        if top_risks:
            risk_df = pd.DataFrame(top_risks)
            display_cols = [
                c
                for c in ["title", "risk_score", "severity", "source_name", "keyword"]
                if c in risk_df.columns
            ]
            if display_cols:
                st.dataframe(
                    risk_df[display_cols].rename(
                        columns={
                            "title": "Title",
                            "risk_score": "Risk Score",
                            "severity": "Severity",
                            "source_name": "Source",
                            "keyword": "Keyword",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
        else:
            st.info("No alerts found for this date.")

        st.divider()

        st.markdown("### Top Entities (Last 24h)")
        top_entities = report.get("top_entities", [])
        if top_entities:
            entity_df = pd.DataFrame(top_entities)
            st.dataframe(
                entity_df.rename(
                    columns={"type": "Type", "value": "Entity", "mention_count": "Mentions"}
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No extracted entities for this period.")

        st.markdown("### New CVEs (Last 24h)")
        new_cves = report.get("new_cves", [])
        if new_cves:
            st.code("\n".join(new_cves), language="text")
        else:
            st.info("No CVEs extracted for this period.")

        st.divider()

        # Emerging Themes
        themes = report.get("emerging_themes", [])
        st.markdown("### Emerging Themes (Frequency Spikes)")
        if themes:
            themes_df = pd.DataFrame(themes)
            fig_themes = px.bar(
                themes_df,
                x="term",
                y="spike_ratio",
                color="spike_ratio",
                color_continuous_scale="OrRd",
                labels={"term": "Keyword", "spike_ratio": "Spike Ratio (vs 7d avg)"},
            )
            fig_themes.update_layout(height=350)
            st.plotly_chart(fig_themes, use_container_width=True)
        else:
            st.info(
                "No keyword spikes detected. Spike detection requires 3+ days of scraping data."
            )

        # Active Threat Actors
        actors = report.get("active_threat_actors", [])
        st.markdown("### Active Threat Actors")
        if actors:
            for actor in actors:
                known = ", ".join(a["name"] for a in actor.get("known_actors", []))
                line = f"- **{actor['keyword']}**: {actor['mentions']} mention(s)"
                if known:
                    line += f" — linked to: {known}"
                st.markdown(line)
        else:
            st.info("No threat actor activity detected for this period.")

    except requests.ConnectionError:
        st.error("Cannot connect to API.")
    except Exception as e:
        st.error(f"Error generating report: {e}")


# ============================================================
# TAB 3: ALERT FEED (with TP/FP classification)
# ============================================================
with tab_alerts:
    st.subheader("Alert Feed")

    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        severity_filter = st.selectbox(
            "Filter by Severity", ["All", "critical", "high", "medium", "low"]
        )
    with filter_col2:
        review_filter = st.selectbox("Filter by Status", ["All", "Unreviewed", "Reviewed"])
    with filter_col3:
        min_score = st.slider("Minimum Risk Score", 0.0, 100.0, 0.0, 5.0)

    params = {"limit": 100, "sort_by": "risk_score"}
    if severity_filter != "All":
        params["severity"] = severity_filter
    if review_filter == "Unreviewed":
        params["reviewed"] = 0
    elif review_filter == "Reviewed":
        params["reviewed"] = 1
    if min_score > 0:
        params["min_score"] = min_score

    try:
        alerts = requests.get(f"{API_URL}/alerts", params=params).json()

        if alerts:
            for alert in alerts:
                severity = alert["severity"]
                icon = SEVERITY_ICONS.get(severity, "⚪")
                reviewed_tag = "✅" if alert["reviewed"] else "🔲"
                score = alert.get("risk_score", 0) or 0
                dup_tag = " [DUP]" if alert.get("duplicate_of") else ""

                with st.expander(
                    f"{icon} {reviewed_tag} [{severity.upper()} {score:.0f}]{dup_tag} {alert['title'][:100]}"
                ):
                    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
                    mc1.write(f"**Risk Score:** {score:.1f}")
                    mc2.write(f"**Source:** {alert.get('source_name', 'Unknown')}")
                    mc3.write(f"**Keyword:** {alert.get('matched_term', 'N/A')}")
                    mc4.write(f"**Published:** {alert.get('published_at') or 'Unknown'}")
                    mc5.write(f"**Ingested:** {alert['created_at']}")

                    if alert.get("duplicate_of"):
                        st.caption(f"Duplicate of alert #{alert['duplicate_of']}")

                    if alert.get("url"):
                        st.write(f"**URL:** {alert['url']}")
                    if alert.get("content"):
                        st.write(f"**Content:** {alert['content'][:500]}...")

                    # Score breakdown
                    try:
                        score_data = requests.get(
                            f"{API_URL}/alerts/{alert['id']}/score",
                            params={"uncertainty": 1, "n": 500},
                        ).json()
                        if "keyword_weight" in score_data:
                            interval = score_data.get("uncertainty") or {}
                            if interval.get("p05") is not None and interval.get("p95") is not None:
                                score_center = score_data.get("final_score", score)
                                st.markdown(
                                    f"**Risk Score:** {score_center:.1f} "
                                    f"(p05={interval['p05']:.1f} / p95={interval['p95']:.1f})"
                                )
                            st.markdown("**Score Breakdown:**")
                            sc1, sc2, sc3, sc4, sc5 = st.columns(5)
                            sc1.metric("Keyword Weight", f"{score_data['keyword_weight']:.1f}")
                            sc2.metric(
                                "Source Credibility", f"{score_data['source_credibility']:.2f}"
                            )
                            sc3.metric("Frequency Factor", f"{score_data['frequency_factor']:.1f}x")
                            sc4.metric("Z-Score", f"{score_data.get('z_score', 0):.2f}")
                            sc5.metric("Recency Factor", f"{score_data['recency_factor']:.2f}")
                            if interval.get("p05") is not None:
                                uc1, uc2, uc3, uc4 = st.columns(4)
                                uc1.metric("MC P05", f"{interval['p05']:.1f}")
                                uc2.metric("MC P50", f"{interval['p50']:.1f}")
                                uc3.metric("MC P95", f"{interval['p95']:.1f}")
                                uc4.metric("MC Std", f"{interval['std']:.2f}")
                    except Exception:
                        pass

                    # Extracted entities + IOCs
                    try:
                        entities = requests.get(f"{API_URL}/alerts/{alert['id']}/entities").json()
                        iocs = requests.get(f"{API_URL}/alerts/{alert['id']}/iocs").json()
                        if entities:
                            st.markdown("**Entities:**")
                            chips = " ".join(
                                f"`{item.get('entity_type', 'unknown')}: {item.get('entity_value', '')}`"
                                for item in entities[:30]
                            )
                            st.markdown(chips)
                        if iocs:
                            st.markdown("**IOCs:**")
                            ioc_df = pd.DataFrame(iocs)
                            cols = [c for c in ["type", "value"] if c in ioc_df.columns]
                            if cols:
                                st.dataframe(
                                    ioc_df[cols].rename(
                                        columns={
                                            "type": "Type",
                                            "value": "Value",
                                        }
                                    ),
                                    use_container_width=True,
                                    hide_index=True,
                                )
                    except Exception:
                        pass

                    # Action buttons: Review + Classify
                    if not alert["reviewed"]:
                        btn_col1, btn_col2, btn_col3 = st.columns(3)
                        with btn_col1:
                            if st.button("Mark Reviewed", key=f"review_{alert['id']}"):
                                requests.patch(f"{API_URL}/alerts/{alert['id']}/review")
                                st.rerun()
                        with btn_col2:
                            if st.button("✅ True Positive", key=f"tp_{alert['id']}"):
                                requests.patch(
                                    f"{API_URL}/alerts/{alert['id']}/classify",
                                    json={"classification": "true_positive"},
                                )
                                st.rerun()
                        with btn_col3:
                            if st.button("❌ False Positive", key=f"fp_{alert['id']}"):
                                requests.patch(
                                    f"{API_URL}/alerts/{alert['id']}/classify",
                                    json={"classification": "false_positive"},
                                )
                                st.rerun()
        else:
            st.info("No alerts found matching your filters.")

    except requests.ConnectionError:
        st.error("Cannot connect to API.")


# ============================================================
# TAB 4: ANALYTICS
# ============================================================
with tab_analytics:
    st.subheader("Threat Analytics")

    # Spike Detection
    st.markdown("### Keyword Frequency Spikes")
    try:
        spikes = requests.get(f"{API_URL}/analytics/spikes", params={"threshold": 1.5}).json()
        if spikes:
            spike_df = pd.DataFrame(spikes)
            fig_spike = px.bar(
                spike_df,
                x="term",
                y="spike_ratio",
                color="today_count",
                color_continuous_scale="Reds",
                labels={
                    "term": "Keyword",
                    "spike_ratio": "Spike Ratio",
                    "today_count": "Today's Count",
                },
                title="Active Keyword Spikes (vs 7-day average)",
            )
            fig_spike.update_layout(height=400)
            st.plotly_chart(fig_spike, use_container_width=True)

            # Show z-score column in table
            display_cols = [
                c
                for c in ["term", "category", "today_count", "avg_7d", "spike_ratio", "z_score"]
                if c in spike_df.columns
            ]
            st.dataframe(
                spike_df[display_cols].rename(
                    columns={
                        "term": "Keyword",
                        "category": "Category",
                        "today_count": "Today",
                        "avg_7d": "7d Avg",
                        "spike_ratio": "Spike Ratio",
                        "z_score": "Z-Score",
                    }
                ),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "No keyword spikes detected above threshold. Spike detection requires 3+ days of scraping history."
            )
    except Exception as e:
        st.error(f"Error loading spike data: {e}")

    st.divider()

    # Keyword Trend Explorer
    st.markdown("### Keyword Trend Explorer")
    try:
        keywords = requests.get(f"{API_URL}/keywords").json()
        if keywords:
            kw_options = {k["term"]: k["id"] for k in keywords}
            selected_term = st.selectbox("Select Keyword", list(kw_options.keys()))
            if selected_term:
                trend = requests.get(
                    f"{API_URL}/analytics/keyword-trend/{kw_options[selected_term]}",
                    params={"days": 14},
                ).json()
                if trend:
                    trend_df = pd.DataFrame(trend)
                    fig_trend = px.line(
                        trend_df,
                        x="date",
                        y="count",
                        title=f"Daily frequency: {selected_term}",
                        markers=True,
                    )
                    fig_trend.update_layout(height=350)
                    st.plotly_chart(fig_trend, use_container_width=True)
                else:
                    st.info("No frequency data yet for this keyword. Run the scraper to populate.")
    except Exception as e:
        st.error(f"Error loading trend data: {e}")

    st.divider()

    # Source Credibility Overview
    st.markdown("### Source Credibility Ratings")
    try:
        sources = requests.get(f"{API_URL}/sources").json()
        if sources:
            source_df = pd.DataFrame(sources)
            if "credibility_score" in source_df.columns:
                source_df = source_df.sort_values("credibility_score", ascending=True)
                fig_cred = px.bar(
                    source_df,
                    x="credibility_score",
                    y="name",
                    orientation="h",
                    color="credibility_score",
                    color_continuous_scale="Greens",
                    labels={"credibility_score": "Credibility Score", "name": "Source"},
                    title="Intelligence Source Credibility",
                )
                fig_cred.update_layout(height=350)
                st.plotly_chart(fig_cred, use_container_width=True)
    except Exception as e:
        st.error(f"Error loading source data: {e}")


# ============================================================
# TAB 5: FORECAST
# ============================================================
with tab_forecast:
    st.subheader("Keyword Frequency Forecast")
    try:
        keywords = requests.get(f"{API_URL}/keywords").json()
        if keywords:
            kw_options = {k["term"]: k["id"] for k in keywords}
            selected_term = st.selectbox("Keyword", list(kw_options.keys()), key="forecast_keyword")
            horizon = st.slider("Horizon (days)", min_value=1, max_value=14, value=7)
            forecast_payload = requests.get(
                f"{API_URL}/analytics/forecast/keyword/{kw_options[selected_term]}",
                params={"horizon": horizon},
            ).json()
            forecast = forecast_payload.get("forecast", [])
            history = forecast_payload.get("history", [])
            quality = forecast_payload.get("quality", {})
            if forecast:
                c1, c2, c3 = st.columns(3)
                c1.metric("Method", forecast[0].get("method", "unknown"))
                c2.metric(
                    "SMAPE",
                    f"{quality.get('smape', 0):.2f}" if quality.get("smape") is not None else "N/A",
                )
                c3.metric("Train Days", quality.get("n_train_days", 0))

                hist_df = pd.DataFrame(history)
                hist_df["series"] = "history"
                fcst_df = pd.DataFrame(forecast).rename(columns={"yhat": "count"})
                fcst_df["series"] = "forecast"
                chart_df = pd.concat(
                    [
                        hist_df[["date", "count", "series"]],
                        fcst_df[["date", "count", "series"]],
                    ],
                    ignore_index=True,
                )
                fig = px.line(chart_df, x="date", y="count", color="series", markers=True)
                fig.add_trace(
                    go.Scatter(
                        x=fcst_df["date"],
                        y=fcst_df["lo"],
                        mode="lines",
                        line={"width": 1, "dash": "dash", "color": "#94a3b8"},
                        name="Forecast Lo",
                    )
                )
                fig.add_trace(
                    go.Scatter(
                        x=fcst_df["date"],
                        y=fcst_df["hi"],
                        mode="lines",
                        line={"width": 1, "dash": "dash", "color": "#94a3b8"},
                        name="Forecast Hi",
                    )
                )
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(fcst_df, use_container_width=True, hide_index=True)
        else:
            st.info("No keywords found.")
    except Exception as e:
        st.error(f"Forecast error: {e}")


# ============================================================
# TAB 6: GRAPH
# ============================================================
with tab_graph:
    st.subheader("Link Analysis Graph")
    days = st.slider("Days", min_value=1, max_value=30, value=7)
    min_score = st.slider("Minimum score", min_value=0.0, max_value=100.0, value=70.0, step=1.0)
    limit_alerts = st.slider("Alert limit", min_value=50, max_value=1000, value=500, step=50)
    try:
        graph_data = requests.get(
            f"{API_URL}/analytics/graph",
            params={"days": days, "min_score": min_score, "limit_alerts": limit_alerts},
        ).json()
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        c1, c2 = st.columns(2)
        c1.metric("Nodes", len(nodes))
        c2.metric("Edges", len(edges))
        if edges:
            edge_df = pd.DataFrame(edges).head(100)
            st.markdown("### Top Edges")
            st.dataframe(edge_df, use_container_width=True, hide_index=True)

            degree = {}
            for edge in edges:
                degree[edge["source"]] = degree.get(edge["source"], 0) + edge["weight"]
                degree[edge["target"]] = degree.get(edge["target"], 0) + edge["weight"]
            degree_df = (
                pd.DataFrame(
                    [{"node": node, "weighted_degree": weight} for node, weight in degree.items()]
                )
                .sort_values("weighted_degree", ascending=False)
                .head(50)
            )
            st.markdown("### Degree Centrality (Weighted)")
            st.dataframe(degree_df, use_container_width=True, hide_index=True)
        else:
            st.info("Graph is empty for current filters.")
    except Exception as e:
        st.error(f"Graph error: {e}")


# ============================================================
# TAB 7: SCORING & EVALUATION
# ============================================================
with tab_scoring:
    st.subheader("Scoring Model & Evaluation Metrics")

    # --- Bayesian vs Static Credibility ---
    st.markdown("### Bayesian vs Static Source Credibility")
    try:
        sources = requests.get(f"{API_URL}/sources").json()
        if sources:
            cred_data = []
            for src in sources:
                alpha = src.get("bayesian_alpha", 2.0) or 2.0
                beta_val = src.get("bayesian_beta", 2.0) or 2.0
                bayesian_cred = round(alpha / (alpha + beta_val), 4)
                static_cred = src.get("credibility_score", 0.5) or 0.5
                cred_data.append(
                    {
                        "Source": src["name"],
                        "Static Credibility": static_cred,
                        "Bayesian Credibility": bayesian_cred,
                        "Alpha": alpha,
                        "Beta": beta_val,
                        "TP": src.get("true_positives", 0) or 0,
                        "FP": src.get("false_positives", 0) or 0,
                    }
                )

            cred_df = pd.DataFrame(cred_data)
            fig_cred = go.Figure()
            fig_cred.add_trace(
                go.Bar(
                    name="Static",
                    x=cred_df["Source"],
                    y=cred_df["Static Credibility"],
                    marker_color="#94a3b8",
                )
            )
            fig_cred.add_trace(
                go.Bar(
                    name="Bayesian",
                    x=cred_df["Source"],
                    y=cred_df["Bayesian Credibility"],
                    marker_color="#f97316",
                )
            )
            fig_cred.update_layout(
                barmode="group",
                height=400,
                yaxis_title="Credibility Score",
                title="Static vs Bayesian Credibility by Source",
            )
            st.plotly_chart(fig_cred, use_container_width=True)

            st.dataframe(cred_df, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Error loading credibility data: {e}")

    st.divider()

    # --- Precision / Recall / F1 ---
    st.markdown("### Precision / Recall / F1 by Source")
    try:
        eval_data = requests.get(f"{API_URL}/analytics/evaluation").json()
        if eval_data:
            eval_df = pd.DataFrame(eval_data)
            display_cols = [
                c
                for c in [
                    "source_name",
                    "true_positives",
                    "false_positives",
                    "total_reviewed",
                    "precision",
                    "recall",
                    "f1_score",
                    "bayesian_credibility",
                ]
                if c in eval_df.columns
            ]
            if display_cols:
                st.dataframe(
                    eval_df[display_cols].rename(
                        columns={
                            "source_name": "Source",
                            "true_positives": "TP",
                            "false_positives": "FP",
                            "total_reviewed": "Reviewed",
                            "precision": "Precision",
                            "recall": "Recall",
                            "f1_score": "F1 Score",
                            "bayesian_credibility": "Bayesian Cred",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )

                # Grouped bar chart for P/R/F1
                if len(eval_df) > 0:
                    fig_prf = go.Figure()
                    fig_prf.add_trace(
                        go.Bar(
                            name="Precision",
                            x=eval_df["source_name"],
                            y=eval_df["precision"],
                            marker_color="#22c55e",
                        )
                    )
                    fig_prf.add_trace(
                        go.Bar(
                            name="Recall",
                            x=eval_df["source_name"],
                            y=eval_df["recall"],
                            marker_color="#3b82f6",
                        )
                    )
                    fig_prf.add_trace(
                        go.Bar(
                            name="F1",
                            x=eval_df["source_name"],
                            y=eval_df["f1_score"],
                            marker_color="#f97316",
                        )
                    )
                    fig_prf.update_layout(
                        barmode="group", height=400, title="Evaluation Metrics by Source"
                    )
                    st.plotly_chart(fig_prf, use_container_width=True)
        else:
            st.info(
                "No evaluation data yet. Classify alerts as TP/FP in the Alert Feed to generate metrics."
            )
    except Exception as e:
        st.error(f"Error loading evaluation data: {e}")

    st.divider()

    # --- Backtest Results ---
    st.markdown("### Backtest: Full Scoring vs Baseline")
    try:
        backtest = requests.get(f"{API_URL}/analytics/backtest").json()
        agg = backtest.get("aggregate", {})

        bc1, bc2, bc3, bc4 = st.columns(4)
        bc1.metric("Baseline Detection Rate", f"{agg.get('baseline_detection_rate', 0):.0%}")
        bc2.metric("Full Model Detection Rate", f"{agg.get('full_detection_rate', 0):.0%}")
        bc3.metric("Baseline Mean Score", f"{agg.get('baseline_mean_score', 0):.1f}")
        bc4.metric("Full Mean Score", f"{agg.get('full_mean_score', 0):.1f}")

        incidents = backtest.get("incidents", [])
        if incidents:
            bt_df = pd.DataFrame(incidents)
            display_cols = [
                c
                for c in [
                    "incident",
                    "expected_severity",
                    "baseline_score",
                    "baseline_severity",
                    "full_score",
                    "full_severity",
                    "score_improvement",
                ]
                if c in bt_df.columns
            ]
            st.dataframe(
                bt_df[display_cols].rename(
                    columns={
                        "incident": "Incident",
                        "expected_severity": "Expected",
                        "baseline_score": "Baseline Score",
                        "baseline_severity": "Baseline Severity",
                        "full_score": "Full Score",
                        "full_severity": "Full Severity",
                        "score_improvement": "Improvement",
                    }
                ),
                use_container_width=True,
                hide_index=True,
            )

            # Chart: baseline vs full scores
            fig_bt = go.Figure()
            fig_bt.add_trace(
                go.Bar(
                    name="Baseline",
                    x=bt_df["incident"],
                    y=bt_df["baseline_score"],
                    marker_color="#94a3b8",
                )
            )
            fig_bt.add_trace(
                go.Bar(
                    name="Full Model",
                    x=bt_df["incident"],
                    y=bt_df["full_score"],
                    marker_color="#f97316",
                )
            )
            fig_bt.update_layout(
                barmode="group",
                height=450,
                title="Baseline vs Full Scoring Model — Golden Dataset",
                yaxis_title="Risk Score",
                xaxis_tickangle=-30,
            )
            st.plotly_chart(fig_bt, use_container_width=True)

    except Exception as e:
        st.error(f"Error loading backtest data: {e}")


# ============================================================
# TAB 8: PERFORMANCE
# ============================================================
with tab_perf:
    st.subheader("Scraping Performance & Deduplication")

    # --- Scrape Run History ---
    st.markdown("### Scrape Run History")
    try:
        perf_data = requests.get(f"{API_URL}/analytics/performance", params={"limit": 20}).json()
        if perf_data:
            perf_df = pd.DataFrame(perf_data)
            display_cols = [
                c
                for c in [
                    "started_at",
                    "scraper_type",
                    "total_alerts",
                    "duration_seconds",
                    "alerts_per_second",
                    "status",
                ]
                if c in perf_df.columns
            ]
            st.dataframe(
                perf_df[display_cols].rename(
                    columns={
                        "started_at": "Started",
                        "scraper_type": "Scraper",
                        "total_alerts": "Alerts",
                        "duration_seconds": "Duration (s)",
                        "alerts_per_second": "Alerts/sec",
                        "status": "Status",
                    }
                ),
                use_container_width=True,
                hide_index=True,
            )

            # Duration trend
            if len(perf_df) > 1 and "duration_seconds" in perf_df.columns:
                fig_dur = px.line(
                    perf_df.sort_values("started_at"),
                    x="started_at",
                    y="duration_seconds",
                    title="Scrape Duration Over Time",
                    markers=True,
                )
                fig_dur.update_layout(height=350, xaxis_title="Run", yaxis_title="Duration (s)")
                st.plotly_chart(fig_dur, use_container_width=True)

            # Alerts per second trend
            if len(perf_df) > 1 and "alerts_per_second" in perf_df.columns:
                fig_aps = px.line(
                    perf_df.sort_values("started_at"),
                    x="started_at",
                    y="alerts_per_second",
                    title="Alerts per Second Over Time",
                    markers=True,
                    color_discrete_sequence=["#f97316"],
                )
                fig_aps.update_layout(height=350, xaxis_title="Run", yaxis_title="Alerts/sec")
                st.plotly_chart(fig_aps, use_container_width=True)
        else:
            st.info("No scrape runs recorded yet. Run the scraper to generate performance data.")
    except Exception as e:
        st.error(f"Error loading performance data: {e}")

    st.divider()

    # --- Deduplication Stats ---
    st.markdown("### Content Deduplication")
    try:
        dedup_data = requests.get(f"{API_URL}/analytics/duplicates").json()

        dc1, dc2, dc3, dc4 = st.columns(4)
        dc1.metric("Total Alerts", dedup_data.get("total_alerts", 0))
        dc2.metric("Unique Alerts", dedup_data.get("unique_alerts", 0))
        dc3.metric("Duplicates", dedup_data.get("duplicates", 0))
        dc4.metric("Dedup Ratio", f"{dedup_data.get('dedup_ratio', 0):.1%}")

        clusters = dedup_data.get("top_clusters", [])
        if clusters:
            st.markdown("**Top Duplicate Clusters:**")
            cluster_df = pd.DataFrame(clusters)
            display_cols = [c for c in ["title", "dup_count"] if c in cluster_df.columns]
            st.dataframe(
                cluster_df[display_cols].rename(
                    columns={
                        "title": "Original Alert",
                        "dup_count": "Duplicate Count",
                    }
                ),
                use_container_width=True,
                hide_index=True,
            )
    except Exception as e:
        st.error(f"Error loading dedup data: {e}")


# ============================================================
# TAB 9: CONFIGURATION
# ============================================================
with tab_config:
    st.subheader("Configuration")

    # --- Keyword Management ---
    st.markdown("### Keyword Management")

    with st.form("add_keyword"):
        kc1, kc2, kc3 = st.columns(3)
        with kc1:
            new_term = st.text_input("New Keyword")
        with kc2:
            new_category = st.selectbox(
                "Category",
                [
                    "general",
                    "malware",
                    "incident",
                    "vulnerability",
                    "threat_actor",
                    "poi",
                    "tactics",
                    "financial",
                ],
            )
        with kc3:
            new_weight = st.slider("Threat Weight", 0.1, 5.0, 1.0, 0.1)
        submitted = st.form_submit_button("Add Keyword")
        if submitted and new_term:
            resp = requests.post(
                f"{API_URL}/keywords",
                json={"term": new_term, "category": new_category, "weight": new_weight},
            )
            if resp.status_code == 200:
                st.success(f"Added keyword: {new_term} (weight: {new_weight})")
                st.rerun()
            else:
                st.error("Keyword already exists or error occurred.")

    try:
        keywords = requests.get(f"{API_URL}/keywords").json()
        if keywords:
            kw_df = pd.DataFrame(keywords)
            display_cols = [
                c for c in ["id", "term", "category", "weight", "active"] if c in kw_df.columns
            ]
            st.dataframe(kw_df[display_cols], use_container_width=True, hide_index=True)
    except Exception:
        pass

    st.divider()

    # --- POI Watchlist ---
    st.markdown("### POI Watchlist")
    st.caption("Add person-of-interest names and aliases as keyword terms (category: poi).")

    with st.form("add_poi_term"):
        pc1, pc2 = st.columns([3, 1])
        with pc1:
            poi_term = st.text_input("POI Term / Alias")
        with pc2:
            poi_weight = st.slider("POI Weight", 0.1, 5.0, 4.0, 0.1)
        poi_submitted = st.form_submit_button("Add POI")
        if poi_submitted and poi_term:
            resp = requests.post(
                f"{API_URL}/keywords",
                json={"term": poi_term, "category": "poi", "weight": poi_weight},
            )
            if resp.status_code == 200:
                st.success(f"Added POI term: {poi_term} (weight: {poi_weight})")
                st.rerun()
            else:
                st.error("POI term already exists or could not be added.")

    try:
        keywords = requests.get(f"{API_URL}/keywords").json()
        poi_keywords = [k for k in keywords if k.get("category") == "poi"]
        if poi_keywords:
            poi_df = pd.DataFrame(poi_keywords)
            st.dataframe(
                poi_df[[c for c in ["id", "term", "weight", "active"] if c in poi_df.columns]].rename(
                    columns={"id": "ID", "term": "Term", "weight": "Weight", "active": "Active"}
                ),
                use_container_width=True,
                hide_index=True,
            )
            remove_map = {f"{k['term']} (id={k['id']})": k["id"] for k in poi_keywords}
            selected_remove = st.selectbox("Remove POI term", ["None"] + list(remove_map.keys()))
            if selected_remove != "None":
                if st.button("Remove Selected POI"):
                    keyword_id = remove_map[selected_remove]
                    resp = requests.delete(f"{API_URL}/keywords/{keyword_id}")
                    if resp.status_code == 200:
                        st.success("POI term removed.")
                        st.rerun()
                    else:
                        st.error("Could not remove POI term.")
        else:
            st.info("No POI terms configured yet.")
    except Exception:
        pass

    st.divider()

    # --- Source Credibility ---
    st.markdown("### Source Credibility")
    try:
        sources = requests.get(f"{API_URL}/sources").json()
        if sources:
            for src in sources:
                sc1, sc2 = st.columns([3, 1])
                cred = src.get("credibility_score", 0.5)
                tp = src.get("true_positives", 0) or 0
                fp = src.get("false_positives", 0) or 0
                sc1.write(
                    f"**{src['name']}** ({src['source_type']}) — "
                    f"Credibility: {cred:.2f} | TP: {tp} | FP: {fp}"
                )
                sc2.write("")  # spacer
    except Exception:
        pass

    st.divider()

    # --- Rescore ---
    st.markdown("### Re-score Alerts")
    st.write(
        "Re-calculate risk scores for all unreviewed alerts using current keyword weights, Bayesian credibility, and Z-score frequency factors."
    )
    if st.button("Re-score All Unreviewed Alerts"):
        try:
            result = requests.post(f"{API_URL}/alerts/rescore").json()
            st.success(f"Rescored {result['alerts_rescored']} alerts.")
        except Exception as e:
            st.error(f"Error: {e}")

    st.divider()

    # --- Threat Actors ---
    st.markdown("### Known Threat Actors")
    try:
        actors = requests.get(f"{API_URL}/threat-actors").json()
        if actors:
            actor_df = pd.DataFrame(actors)
            display_cols = [c for c in ["name", "aliases", "description"] if c in actor_df.columns]
            st.dataframe(actor_df[display_cols], use_container_width=True, hide_index=True)
    except Exception:
        pass
