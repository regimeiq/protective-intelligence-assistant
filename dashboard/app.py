import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

API_URL = "http://localhost:8000"

st.set_page_config(page_title="OSINT Threat Monitor", layout="wide")
st.title("OSINT Threat Monitor")

# --- SUMMARY METRICS ---
try:
    summary = requests.get(f"{API_URL}/alerts/summary").json()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", summary["total_alerts"])
    col2.metric("Unreviewed", summary["unreviewed"])
    col3.metric(
        "Critical",
        summary["by_severity"].get("critical", 0),
    )
    col4.metric(
        "High",
        summary["by_severity"].get("high", 0),
    )

    # --- SEVERITY BREAKDOWN ---
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
        color_map = {
            "critical": "#dc2626",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
        }
        fig_severity = px.bar(
            severity_df,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map=color_map,
        )
        fig_severity.update_layout(showlegend=False)
        st.plotly_chart(fig_severity, use_container_width=True)

    # --- SOURCE BREAKDOWN ---
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Alerts by Source")
        if summary["by_source"]:
            source_df = pd.DataFrame(
                list(summary["by_source"].items()), columns=["Source", "Count"]
            )
            fig_source = px.pie(source_df, values="Count", names="Source", hole=0.4)
            st.plotly_chart(fig_source, use_container_width=True)

    with col_right:
        st.subheader("Top Matched Keywords")
        if summary["top_keywords"]:
            kw_df = pd.DataFrame(
                list(summary["top_keywords"].items()), columns=["Keyword", "Count"]
            )
            kw_df = kw_df.sort_values("Count", ascending=True)
            fig_kw = px.bar(kw_df, x="Count", y="Keyword", orientation="h")
            st.plotly_chart(fig_kw, use_container_width=True)

except requests.ConnectionError:
    st.error("Cannot connect to API. Make sure the API server is running on port 8000.")
    st.stop()

# --- ALERT FEED ---
st.subheader("Alert Feed")

filter_col1, filter_col2 = st.columns(2)
with filter_col1:
    severity_filter = st.selectbox(
        "Filter by Severity", ["All", "critical", "high", "medium", "low"]
    )
with filter_col2:
    review_filter = st.selectbox(
        "Filter by Status", ["All", "Unreviewed", "Reviewed"]
    )

params = {"limit": 100}
if severity_filter != "All":
    params["severity"] = severity_filter
if review_filter == "Unreviewed":
    params["reviewed"] = 0
elif review_filter == "Reviewed":
    params["reviewed"] = 1

try:
    alerts = requests.get(f"{API_URL}/alerts", params=params).json()

    if alerts:
        for alert in alerts:
            severity = alert["severity"]
            severity_colors = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }
            icon = severity_colors.get(severity, "⚪")
            reviewed_tag = "✅" if alert["reviewed"] else "🔲"

            with st.expander(
                f"{icon} {reviewed_tag} [{severity.upper()}] {alert['title'][:100]}"
            ):
                st.write(f"**Source:** {alert.get('source_name', 'Unknown')}")
                st.write(f"**Matched Keyword:** {alert.get('matched_term', 'N/A')}")
                st.write(f"**Time:** {alert['created_at']}")
                if alert.get("url"):
                    st.write(f"**URL:** {alert['url']}")
                if alert.get("content"):
                    st.write(f"**Content:** {alert['content'][:300]}...")
                if not alert["reviewed"]:
                    if st.button(f"Mark Reviewed", key=f"review_{alert['id']}"):
                        requests.patch(f"{API_URL}/alerts/{alert['id']}/review")
                        st.rerun()
    else:
        st.info("No alerts found matching your filters.")

except requests.ConnectionError:
    st.error("Cannot connect to API.")

# --- KEYWORD MANAGEMENT ---
st.subheader("Keyword Management")

with st.form("add_keyword"):
    new_term = st.text_input("New Keyword")
    new_category = st.selectbox(
        "Category",
        ["general", "malware", "incident", "vulnerability", "actor", "tactics", "threat", "financial", "source"],
    )
    submitted = st.form_submit_button("Add Keyword")
    if submitted and new_term:
        resp = requests.post(
            f"{API_URL}/keywords",
            json={"term": new_term, "category": new_category},
        )
        if resp.status_code == 200:
            st.success(f"Added keyword: {new_term}")
            st.rerun()
        else:
            st.error("Keyword already exists or error occurred.")

try:
    keywords = requests.get(f"{API_URL}/keywords").json()
    if keywords:
        kw_display = pd.DataFrame(keywords)[["id", "term", "category", "active"]]
        st.dataframe(kw_display, use_container_width=True)
except requests.ConnectionError:
    st.error("Cannot connect to API.")
