from collections import defaultdict
from datetime import datetime, timedelta

from database.init_db import get_connection


def build_graph(days=7, min_score=70.0, limit_alerts=500):
    """
    Build a compact link-analysis graph for high-risk recent alerts.
    """
    safe_days = max(1, min(int(days), 30))
    safe_limit = max(1, min(int(limit_alerts), 2000))
    cutoff = (datetime.utcnow() - timedelta(days=safe_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    alerts = conn.execute(
        """SELECT a.id, a.keyword_id, k.term AS keyword_term,
                  a.source_id, s.name AS source_name, a.risk_score
        FROM alerts a
        JOIN keywords k ON a.keyword_id = k.id
        JOIN sources s ON a.source_id = s.id
        WHERE a.duplicate_of IS NULL
          AND COALESCE(a.published_at, a.created_at) >= ?
          AND a.risk_score >= ?
        ORDER BY a.risk_score DESC
        LIMIT ?""",
        (cutoff, float(min_score), safe_limit),
    ).fetchall()

    node_weights = defaultdict(float)
    node_meta = {}
    edge_weights = defaultdict(float)

    def add_node(node_id, label, node_type, weight):
        node_weights[node_id] += weight
        node_meta[node_id] = {"id": node_id, "label": label, "type": node_type}

    def add_edge(source, target, kind, weight):
        edge_weights[(source, target, kind)] += weight

    for alert in alerts:
        alert_weight = float(alert["risk_score"] or 0.0)
        source_node = f"source:{alert['source_id']}"
        keyword_node = f"keyword:{alert['keyword_id']}"
        add_node(source_node, alert["source_name"], "source", alert_weight)
        add_node(keyword_node, alert["keyword_term"], "keyword", alert_weight)
        add_edge(source_node, keyword_node, "source_keyword", alert_weight)

        entities = conn.execute(
            """SELECT e.id, e.type, e.value
            FROM alert_entities ae
            JOIN entities e ON e.id = ae.entity_id
            WHERE ae.alert_id = ?""",
            (alert["id"],),
        ).fetchall()
        for entity in entities:
            entity_node = f"entity:{entity['type']}:{entity['value']}"
            add_node(entity_node, entity["value"], f"entity:{entity['type']}", alert_weight)
            add_edge(keyword_node, entity_node, "keyword_entity", alert_weight)

        iocs = conn.execute(
            """SELECT i.id, i.type, i.value
            FROM alert_iocs ai
            JOIN iocs i ON i.id = ai.ioc_id
            WHERE ai.alert_id = ?""",
            (alert["id"],),
        ).fetchall()
        for ioc in iocs:
            ioc_node = f"ioc:{ioc['type']}:{ioc['value']}"
            add_node(ioc_node, ioc["value"], f"ioc:{ioc['type']}", alert_weight)
            add_edge(keyword_node, ioc_node, "keyword_ioc", alert_weight)

    conn.close()

    nodes = []
    for node_id, meta in node_meta.items():
        nodes.append(
            {
                "id": node_id,
                "label": meta["label"],
                "type": meta["type"],
                "weight": round(node_weights[node_id], 3),
            }
        )
    nodes.sort(key=lambda x: x["weight"], reverse=True)

    edges = []
    for (source, target, kind), weight in edge_weights.items():
        edges.append(
            {
                "source": source,
                "target": target,
                "kind": kind,
                "weight": round(weight, 3),
            }
        )
    edges.sort(key=lambda x: x["weight"], reverse=True)

    return {"nodes": nodes, "edges": edges}
