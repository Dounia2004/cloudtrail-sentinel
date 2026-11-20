"""Dashboard SOC (Streamlit) : alertes actives, score maximal, timeline, graphiques.

Lancement (l'API doit tourner) :
    streamlit run src/dashboard/app.py
Variable optionnelle : SENTINEL_API (défaut http://127.0.0.1:8000).
"""
from __future__ import annotations

import os
import time

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

API = os.environ.get("SENTINEL_API", "http://127.0.0.1:8000")
SEVERITY_ORDER = ["critique", "élevée", "moyenne", "faible"]
SEVERITY_COLORS = {
    "critique": "#d62728",
    "élevée": "#ff7f0e",
    "moyenne": "#f2c744",
    "faible": "#7f7f7f",
}
TABLE_COLUMNS = [
    "alert_id",
    "identity",
    "severity",
    "score",
    "rule_id",
    "mitre_technique",
    "detection_source",
    "first_seen",
    "description",
]


def api_get(path: str, **params):
    params = {k: v for k, v in params.items() if v not in (None, "")}
    response = httpx.get(f"{API}{path}", params=params, timeout=10)
    response.raise_for_status()
    return response.json()


def timeline_chart(entries: list[dict], margin_hours: int):
    df = pd.DataFrame(entries)
    df["time"] = pd.to_datetime(df["time"], utc=True)
    alert_times = df.loc[df["kind"] == "alert", "time"]
    if len(alert_times):
        margin = pd.Timedelta(hours=margin_hours)
        start, end = alert_times.min() - margin, alert_times.max() + margin
        df = df[(df["time"] >= start) & (df["time"] <= end)]
    else:
        df = df.tail(100)
    df["taille"] = df["score"].fillna(25) if "score" in df else 25
    fig = px.scatter(
        df,
        x="time",
        y="label",
        color="kind",
        size="taille",
        hover_data=["detail"],
        color_discrete_map={"alert": "#d62728", "event": "#1f77b4"},
        title="Chronologie (événements et alertes)",
    )
    fig.update_layout(yaxis_title="", xaxis_title="")
    return fig


st.set_page_config(page_title="CloudTrail Sentinel", layout="wide")
st.title("CloudTrail Sentinel : dashboard SOC")

try:
    stats = api_get("/stats")
except httpx.HTTPError as exc:
    st.error(f"API injoignable ({API}). Lancez : uvicorn src.api.main:app\n\n{exc}")
    st.stop()

with st.sidebar:
    st.header("Filtres")
    min_score = st.slider("Score minimal", 0, 100, 40)
    all_alerts = api_get("/alerts")
    identities = sorted({a["identity"] for a in all_alerts})
    identity = st.selectbox("Identité", ["(toutes)", *identities])
    margin_hours = st.slider("Marge de la chronologie (heures)", 1, 24, 3)
    auto = st.checkbox("Rafraîchir automatiquement (2 s)")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alertes actives", stats["alerts_active"])
c2.metric("Score maximal", stats["max_score"])
c3.metric("Incidents", stats["incidents"])
c4.metric("Identités concernées", stats["identities_affected"])

selected = None if identity == "(toutes)" else identity
alerts = api_get("/alerts", min_score=min_score, identity=selected)

st.subheader(f"Alertes ({len(alerts)})")
if alerts:
    table = pd.DataFrame(alerts)[TABLE_COLUMNS]
    st.dataframe(table, hide_index=True)
else:
    st.info("Aucune alerte pour ces filtres. Lancez `python -m src.scoring.scoring` d'abord.")

left, right = st.columns(2)
if stats["by_rule"]:
    by_rule = pd.DataFrame(
        sorted(stats["by_rule"].items(), key=lambda kv: -kv[1]), columns=["règle", "alertes"]
    )
    left.plotly_chart(px.bar(by_rule, x="règle", y="alertes", title="Alertes par règle"))
if stats["by_severity"]:
    by_sev = pd.DataFrame(list(stats["by_severity"].items()), columns=["sévérité", "alertes"])
    right.plotly_chart(
        px.pie(
            by_sev,
            names="sévérité",
            values="alertes",
            color="sévérité",
            color_discrete_map=SEVERITY_COLORS,
            category_orders={"sévérité": SEVERITY_ORDER},
            title="Répartition par sévérité",
        )
    )

st.subheader("Chronologie d'une identité")
choices = identities or []
default = selected if selected in choices else (choices[0] if choices else None)
if default:
    who = st.selectbox(
        "Identité à investiguer", choices, index=choices.index(default), key="timeline_identity"
    )
    data = api_get(f"/identities/{who}/timeline")
    for incident in data["incidents"]:
        st.warning(
            f"{incident['incident_id']} : {incident['n_alerts']} alerte(s), "
            f"sévérité {incident['severity']} (score {incident['risk_score']}), "
            f"techniques {', '.join(incident['techniques']) or 'n/a'}"
        )
    if data["entries"]:
        st.plotly_chart(timeline_chart(data["entries"], margin_hours))
else:
    st.caption("Aucune identité avec alerte pour le moment.")

if auto:
    time.sleep(2)
    st.rerun()
