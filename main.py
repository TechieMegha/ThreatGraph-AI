import os
from pathlib import Path

import redis
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

load_dotenv()

app = FastAPI(
    title="ThreatGraph AI",
    description="A graph-powered cybersecurity investigation agent",
    version="0.4.0",
)

graph_db = redis.Redis(
    host=os.getenv("FALKORDB_HOST", "localhost"),
    port=int(os.getenv("FALKORDB_PORT", "6379")),
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=3,
)

GRAPH_NAME = os.getenv("FALKORDB_GRAPH", "threatgraph")
BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# --------------------------------------------------
# Graph database helpers
# --------------------------------------------------

def run_graph_query(query):
    """Execute a read query and return its rows."""
    result = graph_db.execute_command(
        "GRAPH.QUERY", GRAPH_NAME, query
    )

    if not isinstance(result, (list, tuple)) or len(result) < 2:
        return []

    rows = result[1]
    return rows if isinstance(rows, (list, tuple)) else []


def escape_value(value):
    """Escape a string before placing it inside a Cypher string literal."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def get_count(query):
    """Return the first numeric count from a graph query."""
    rows = run_graph_query(query)

    if not rows or not rows[0]:
        return 0

    return int(rows[0][0] or 0)


# --------------------------------------------------
# Shared risk scoring
# --------------------------------------------------

def calculate_risk(reputation, alert_severity):
    """Rule-based score for the synthetic demonstration dataset."""
    risk_score = 0
    reasons = []

    if reputation == "suspicious":
        risk_score += 50
        reasons.append("IP reputation is suspicious.")

    if alert_severity == "HIGH":
        risk_score += 30
        reasons.append("A HIGH severity alert is linked to this IP.")
    elif alert_severity == "MEDIUM":
        risk_score += 15
        reasons.append("A MEDIUM severity alert is linked to this IP.")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    if not reasons:
        reasons.append(
            "No suspicious IP reputation or linked alert found."
        )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reason": " ".join(reasons),
    }


def make_finding(row):
    (
        user,
        user_id,
        device,
        ip,
        reputation,
        alert_id,
        alert_type,
        alert_severity,
    ) = row

    risk = calculate_risk(reputation, alert_severity)

    return {
        "user": user,
        "user_id": user_id,
        "device": device,
        "ip": ip,
        "reputation": reputation,
        "severity": risk["severity"],
        "risk_score": risk["risk_score"],
        "reason": risk["reason"],
        "alert": {
            "id": alert_id,
            "type": alert_type,
            "severity": alert_severity,
        } if alert_id else None,
    }


# --------------------------------------------------
# Basic endpoints
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "project": "ThreatGraph AI",
        "status": "running",
        "database": "FalkorDB",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/db-check")
def db_check():
    try:
        response = graph_db.ping()
        return {
            "database": "FalkorDB",
            "connected": bool(response),
            "response": response,
        }
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Database connection failed: {exc}",
        ) from exc


# --------------------------------------------------
# Live graph statistics
# --------------------------------------------------

@app.get("/graph-stats")
def graph_stats():
    """Calculate node and relationship counts directly from FalkorDB."""
    try:
        node_labels = ["User", "Device", "IPAddress", "Alert"]

        nodes_by_label = {
            label: get_count(
                f"MATCH (n:{label}) RETURN count(n)"
            )
            for label in node_labels
        }

        total_nodes = get_count(
            "MATCH (n) RETURN count(n)"
        )

        total_relationships = get_count(
            "MATCH ()-[r]->() RETURN count(r)"
        )

        relationship_rows = run_graph_query(
            """
            MATCH ()-[r]->()
            RETURN type(r), count(r)
            """
        )

        relationships_by_type = {
            str(row[0]): int(row[1])
            for row in relationship_rows
            if len(row) >= 2 and row[0] is not None
        }

        return {
            "status": "success",
            "graph": GRAPH_NAME,
            "total_nodes": total_nodes,
            "total_relationships": total_relationships,
            "nodes_by_label": nodes_by_label,
            "relationships_by_type": relationships_by_type,
            "note": (
                "Counts are queried from FalkorDB at request time. "
                "Data is synthetic demonstration data."
            ),
        }

    except (redis.RedisError, TypeError, ValueError, IndexError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not read graph statistics: {exc}",
        ) from exc


# --------------------------------------------------
# Seed a small demo graph
# --------------------------------------------------

@app.post("/seed-demo")
def seed_demo():
    query = """
    MERGE (u:User {id: 'megha_test'})
    SET u.name = 'Demo User'

    MERGE (d:Device {id: 'DEV-001'})
    SET d.type = 'Laptop'

    MERGE (ip:IPAddress {address: '203.0.113.42'})
    SET ip.reputation = 'suspicious'

    MERGE (u)-[:USES_DEVICE]->(d)
    MERGE (d)-[:CONNECTED_FROM]->(ip)

    RETURN u.id AS user, d.id AS device, ip.address AS ip
    """

    try:
        result = graph_db.execute_command(
            "GRAPH.QUERY", GRAPH_NAME, query
        )
        return {
            "status": "success",
            "graph": GRAPH_NAME,
            "result": result,
            "note": "Synthetic demonstration data only.",
        }
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Graph query failed: {exc}",
        ) from exc


# --------------------------------------------------
# Inspect graph connections
# --------------------------------------------------

@app.get("/graph-check")
def graph_check():
    query = """
    MATCH (u:User)-[:USES_DEVICE]->(d:Device)
          -[:CONNECTED_FROM]->(ip:IPAddress)
    RETURN u.name AS user,
           d.id AS device,
           ip.address AS ip,
           ip.reputation AS reputation
    """

    try:
        return {
            "status": "success",
            "graph": GRAPH_NAME,
            "result": graph_db.execute_command(
                "GRAPH.QUERY", GRAPH_NAME, query
            ),
        }
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Graph query failed: {exc}",
        ) from exc


# --------------------------------------------------
# Seed the synthetic security dataset
# --------------------------------------------------

@app.post("/seed-dataset")
def seed_dataset():
    query = """
    MERGE (u1:User {id: 'user_001'})
    SET u1.name = 'Asha Verma', u1.department = 'Finance'

    MERGE (u2:User {id: 'user_002'})
    SET u2.name = 'Ravi Kumar', u2.department = 'Engineering'

    MERGE (u3:User {id: 'user_003'})
    SET u3.name = 'Neha Singh', u3.department = 'HR'

    MERGE (d1:Device {id: 'DEV-101'})
    SET d1.type = 'Laptop'

    MERGE (d2:Device {id: 'DEV-102'})
    SET d2.type = 'Laptop'

    MERGE (d3:Device {id: 'DEV-103'})
    SET d3.type = 'Workstation'

    MERGE (d4:Device {id: 'DEV-104'})
    SET d4.type = 'Laptop'

    MERGE (ip1:IPAddress {address: '203.0.113.42'})
    SET ip1.reputation = 'suspicious', ip1.risk_score = 90

    MERGE (ip2:IPAddress {address: '198.51.100.23'})
    SET ip2.reputation = 'suspicious', ip2.risk_score = 75

    MERGE (ip3:IPAddress {address: '192.0.2.10'})
    SET ip3.reputation = 'clean', ip3.risk_score = 5

    MERGE (a1:Alert {id: 'ALT-001'})
    SET a1.type = 'Suspicious Login', a1.severity = 'HIGH'

    MERGE (a2:Alert {id: 'ALT-002'})
    SET a2.type = 'Repeated Login Failures', a2.severity = 'MEDIUM'

    MERGE (u1)-[:USES_DEVICE]->(d1)
    MERGE (u2)-[:USES_DEVICE]->(d2)
    MERGE (u3)-[:USES_DEVICE]->(d3)
    MERGE (u3)-[:USES_DEVICE]->(d4)

    MERGE (d1)-[:CONNECTED_FROM]->(ip1)
    MERGE (d2)-[:CONNECTED_FROM]->(ip1)
    MERGE (d3)-[:CONNECTED_FROM]->(ip3)
    MERGE (d4)-[:CONNECTED_FROM]->(ip2)

    MERGE (ip1)-[:HAS_ALERT]->(a1)
    MERGE (ip2)-[:HAS_ALERT]->(a2)

    MERGE (a1)-[:TARGETS_USER]->(u1)
    MERGE (a1)-[:TARGETS_USER]->(u2)
    MERGE (a2)-[:TARGETS_USER]->(u3)

    RETURN u1.name AS user1,
           u2.name AS user2,
           u3.name AS user3
    """

    try:
        result = graph_db.execute_command(
            "GRAPH.QUERY", GRAPH_NAME, query
        )
        return {
            "status": "success",
            "message": "Synthetic security dataset created or refreshed",
            "graph": GRAPH_NAME,
            "result": result,
            "note": "This is synthetic demo data, not live threat intelligence.",
        }
    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Dataset creation failed: {exc}",
        ) from exc


# --------------------------------------------------
# Investigate a user
# --------------------------------------------------

@app.get("/investigate/{user_id}")
def investigate(user_id: str):
    safe_user_id = escape_value(user_id)

    query = f"""
    MATCH (u:User {{id: '{safe_user_id}'}})
          -[:USES_DEVICE]->(d:Device)
          -[:CONNECTED_FROM]->(ip:IPAddress)
    OPTIONAL MATCH (ip)-[:HAS_ALERT]->(a:Alert)
    RETURN u.name AS user,
           u.id AS user_id,
           d.id AS device,
           ip.address AS ip,
           ip.reputation AS reputation,
           a.id AS alert_id,
           a.type AS alert_type,
           a.severity AS alert_severity
    """

    try:
        rows = run_graph_query(query)

        if not rows:
            return {
                "status": "not_found",
                "message": "No connected threat data found for this user.",
            }

        findings = [make_finding(row) for row in rows]

        return {
            "status": "success",
            "investigation": findings,
            "summary": {
                "user_id": user_id,
                "evidence_paths": len(findings),
                "suspicious_ips": len({
                    item["ip"] for item in findings
                    if item["reputation"] == "suspicious"
                }),
                "linked_alerts": len({
                    item["alert"]["id"] for item in findings
                    if item["alert"]
                }),
                "highest_risk_score": max(
                    item["risk_score"] for item in findings
                ),
            },
        }

    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Investigation query failed: {exc}",
        ) from exc


# --------------------------------------------------
# Investigate an IP address
# --------------------------------------------------

@app.get("/investigate-ip/{ip_address}")
def investigate_ip(ip_address: str):
    safe_ip = escape_value(ip_address)

    query = f"""
    MATCH (u:User)-[:USES_DEVICE]->(d:Device)
          -[:CONNECTED_FROM]->(ip:IPAddress
          {{address: '{safe_ip}'}})
    OPTIONAL MATCH (ip)-[:HAS_ALERT]->(a:Alert)
    RETURN u.name AS user,
           u.id AS user_id,
           d.id AS device,
           ip.address AS ip,
           ip.reputation AS reputation,
           a.id AS alert_id,
           a.type AS alert_type,
           a.severity AS alert_severity
    """

    try:
        rows = run_graph_query(query)

        if not rows:
            return {
                "status": "not_found",
                "message": "No connected users or threats found for this IP.",
            }

        findings = [make_finding(row) for row in rows]
        connected_users = sorted({
            item["user_id"] for item in findings
        })
        linked_alerts = sorted({
            item["alert"]["id"] for item in findings
            if item["alert"]
        })

        return {
            "status": "success",
            "ip": ip_address,
            "connected_users": len(connected_users),
            "connected_user_ids": connected_users,
            "investigation": findings,
            "summary": {
                "ip_reputation": findings[0]["reputation"],
                "connected_users": len(connected_users),
                "evidence_paths": len(findings),
                "linked_alerts": len(linked_alerts),
                "alert_ids": linked_alerts,
                "highest_risk_score": max(
                    item["risk_score"] for item in findings
                ),
                "explanation": (
                    f"This IP is connected to {len(connected_users)} "
                    "distinct user(s) through device relationships."
                ),
            },
        }

    except redis.RedisError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"IP investigation failed: {exc}",
        ) from exc


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={},
    )
