# ThreatGraph AI

**A Graph-Powered Cybersecurity Investigation Agent**

ThreatGraph AI is a cybersecurity investigation prototype powered by FalkorDB. It helps analysts explore relationships between users, devices, IP addresses, and security alerts to understand how suspicious activity may be connected.

The project uses a synthetic dataset and an interactive dashboard to demonstrate graph-based investigation workflows.

## Features

- Graph-based security data storage using FalkorDB.
- User investigations across connected devices, IP addresses, and alerts.
- IP investigations to discover connected users and evidence paths.
- Heuristic risk scoring and severity classification.
- FastAPI backend with interactive API documentation.
- Interactive web dashboard with investigation controls and graph visualization.
- Repeatable synthetic dataset seeding using Cypher `MERGE` queries.

## Tech Stack

- Python
- FastAPI
- FalkorDB
- Redis Python client
- HTML, CSS, and JavaScript
- Docker

## Architecture

1. Synthetic security records are stored in FalkorDB.
2. Users are connected to devices, and devices are connected to IP addresses.
3. IP addresses can be connected to security alerts.
4. FastAPI executes graph queries and returns investigation evidence.
5. The dashboard presents findings, graph relationships, and heuristic risk scores.

## Graph Data Model

### Nodes

- `User`: A user account being investigated.
- `Device`: A device associated with a user.
- `IPAddress`: An IP address with a demonstration reputation.
- `Alert`: A synthetic security alert.

### Relationships

```cypher
(:User)-[:USES_DEVICE]->(:Device)
(:Device)-[:CONNECTED_FROM]->(:IPAddress)
(:IPAddress)-[:HAS_ALERT]->(:Alert)
(:Alert)-[:TARGETS_USER]->(:User)
```

### Example Cypher Queries

Create or update a user node:

```cypher
MERGE (u:User {user_id: 'user_001'})
SET u.name = 'Asha Verma',
    u.department = 'Finance'
RETURN u
```

Trace a user's connected devices, IP addresses, and alerts:

```cypher
MATCH (u:User {user_id: 'user_001'})
      -[:USES_DEVICE]->(d:Device)
      -[:CONNECTED_FROM]->(ip:IPAddress)
OPTIONAL MATCH (ip)-[:HAS_ALERT]->(a:Alert)
RETURN u, d, ip, a
```

Find users connected to a particular IP through their devices:

```cypher
MATCH (u:User)-[:USES_DEVICE]->(d:Device)
      -[:CONNECTED_FROM]->(ip:IPAddress {address: '203.0.113.42'})
OPTIONAL MATCH (ip)-[:HAS_ALERT]->(a:Alert)
RETURN u, d, ip, a
```

These examples illustrate the graph model and investigation patterns. The application uses its own Cypher queries in `main.py`; refer to that file for the implementation.

## Prerequisites

- Python 3.11 or later
- Docker Desktop
- A running FalkorDB instance
- Git, if cloning the repository

## Setup

### 1. Start FalkorDB

If you already have the demo container, start it:

```powershell
docker start threatgraph-db
```

If the container does not exist, create a FalkorDB instance using the official [FalkorDB documentation](https://docs.falkordb.com/).

### 2. Create a virtual environment

From the project directory, run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env` and check the configuration:

```dotenv
FALKORDB_HOST=localhost
FALKORDB_PORT=6379
FALKORDB_GRAPH=threatgraph
```

Ensure the database is reachable using the configured host and port.

**Never commit your `.env` file or credentials to a public repository.**

### 5. Start the API

```powershell
python -m uvicorn main:app --reload
```

## Run the Demo

Open the dashboard:

http://127.0.0.1:8000/dashboard

Load the synthetic dataset from the dashboard, or use the API:

```powershell
curl.exe -X POST http://127.0.0.1:8000/seed-dataset
```

Investigate a user:

```text
GET /investigate/user_001
GET /investigate/user_002
GET /investigate/user_003
```

Investigate an IP address:

```text
GET /investigate-ip/203.0.113.42
```

Interactive API documentation:

http://127.0.0.1:8000/docs

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Project status |
| GET | `/health` | API health check |
| GET | `/db-check` | Database connectivity check |
| POST | `/seed-demo` | Add a small demo graph |
| POST | `/seed-dataset` | Load the synthetic dataset |
| GET | `/graph-stats` | Retrieve graph statistics |
| GET | `/graph-check` | Inspect graph connections |
| GET | `/investigate/{user_id}` | Investigate a user |
| GET | `/investigate-ip/{ip_address}` | Investigate an IP |
| GET | `/dashboard` | Open the web dashboard |

## Risk Scoring

The prototype uses a simple heuristic risk score:

| Evidence | Score contribution |
|---|---:|
| Suspicious IP reputation | +50 |
| Linked HIGH severity alert | +30 |
| Linked MEDIUM severity alert | +15 |

The score is capped at 100. Severity is classified as:

- **HIGH:** 70–100
- **MEDIUM:** 40–69
- **LOW:** 1–39
- **INFO:** 0

These values are demonstration logic, not a validated security risk model. They should not be used for production security decisions.

## Limitations

- The dataset is synthetic and intended for demonstration.
- The example IP addresses belong to documentation-only address ranges and do not indicate real malicious infrastructure.
- Risk scores are heuristic and have not been validated for operational security use.
- Production use would require stronger input validation, authentication, authorization, audit logging, and a validated risk model.

## Project Structure

```text
ThreatGraph-AI/
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   └── dashboard.html
└── static/
    ├── dashboard.css
    └── dashboard.js
```

## Future Improvements

- Integrate verified threat-intelligence sources.
- Add investigation timelines and richer graph exploration.
- Add authentication, authorization, and audit logging.
- Expand automated tests and deployment options.
- Validate risk-scoring logic against realistic security scenarios.

## Disclaimer

ThreatGraph AI is a hackathon demonstration project. It does not replace professional security monitoring or incident response.

## License

No license has been selected yet. A license can be added if the project owner wishes to grant others permission to reuse or redistribute the code.
