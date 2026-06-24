# CTI-Data-Parsing & CTIHub Platform

An advanced Threat Intelligence ingestion and visual analysis platform. It features both a high-throughput parallel CTI database pipeline and a full **CTIHub Platform** equipped with simulated and live APIs connectors, a STIX 2.1 ingestion engine, and an interactive cybersecurity knowledge graph.

## 🚀 CTIHub Platform Features

- **Standard CTIHub Connectors**: 11 built-in connectors (MITRE ATT&CK, AbuseIPDB, ThreatFox, AlienVault OTX, MalwareBazaar, CVE/NVD, MISP Event Import, URLhaus Live, IPinfo GeoIP, CISA Security Alerts, Shodan Open Port Scanner) that fetch threat intel live via APIs or databases.
- **STIX 2.1 Compliant Ingest Engine**: Automatically validates, parses, normalises, and builds relationships between threat indicators, malware, campaigns, and actors.
- **Interactive Knowledge Graph**: Beautiful, responsive, force-directed threat relationship graph rendered using Vis.js.
- **Premium Dark Cyber Dashboard**: Sleek dashboard displaying real-time metrics, confidence distributions, and live ingestion feeds.
- **REST APIs**: Full OpenAPI/FastAPI endpoints for querying indicators, exploring relationships, and managing connector runners.

---

## Quick Start (CTIHub Platform)

### 1. Launch the platform:
```bash
python run_platform.py 8001
```
This script will initialize the SQLite database, start the FastAPI server, and automatically open the dashboard in your default browser at `http://127.0.0.1:8001/`.

### 2. Ingest baseline data:
- Go to the **Connectors** tab.
- Click **Run Connector** on **MITRE ATT&CK Baseline Data** to seed the threat library (Malware, Actors, CVEs, and relationship edges).
- Go to the **Knowledge Graph** or **Dashboard** to explore your threat intelligence graph!

---

## Project Structure

```

cti-data-platform/
├── config/
│   ├── database_config.py       # PostgreSQL connection strings
│   └── query_config.py          # SQL queries per DB
├── transformer/
│   ├── database_manager.py      # Connection handling
│   └── stix_transformer.py      # STIX bundle creator
├── ctihub/                      # CTIHub UI & API platform
│   ├── connectors.py            # API/DB Connectors & threat feeds
│   ├── database.py              # SQLite database session and setup
│   ├── ingest.py                # STIX 2.1 ingest engine
│   ├── models.py                # Database models for STIX objects
│   ├── server.py                # FastAPI web server and REST APIs
│   └── ui/                      # Frontend web app (HTML, CSS, JS)
├── cti_processor.py             # Main runner (CLI interface)
├── setup.sh                     # Dependency installer + setup
├── requirements.txt             # Python dependencies
├── output/                      # Output JSON files
└── README.md


```


## Setup

```bash
git clone <your_repo_url>
cd cti-data-platform
chmod +x setup.sh
./setup.sh
source venv/bin/activate
````

* Edit `config/database_config.py` with PostgreSQL URIs
* Edit `config/query_config.py` to map each DB to a SQL query



## Usage

### Run all databases in parallel:

```bash
python cti_processor.py --all
```

### Test all database connections:

```bash
python cti_processor.py --test
```

### Run a single DB + custom query:

```bash
python cti_processor.py -d abuseipdb_blacklisted -q "SELECT * FROM table WHERE confidence > 80"
```


## Output

All JSON files are saved in `output/` with timestamped names:

* `stix_<source>_<timestamp>.json`
* `llm_ready_<source>_<timestamp>.json`




## Notes

* This adheres to [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) standards.
* All data transformations are performed in-memory using pure Python.
* Designed to be ML pipeline-friendly and scalable to more sources.
