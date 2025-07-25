# CTI-Data-Parsing

-  LLM-Ready JSON output (structured for ML/NLP)
-  STIX 2.1-compliant indicators for interoperability
-  Simultaneous processing of 13 threat intel sources
-  Native PostgreSQL support (no Docker needed)
-  Robust error handling and retry logic
-  Timestamped output file generation



## Project Structure

```

cti-data-platform/
├── config/
│   ├── database\_config.py       # PostgreSQL connection strings
│   └── query\_config.py          # SQL queries per DB
├── transformer/
│   ├── database\_manager.py      # Connection handling
│   └── stix\_transformer.py      # STIX bundle creator
├── cti\_processor.py             # Main runner (CLI interface)
├── combine\_output.py            # (Optional) Combines all outputs into one
├── setup.sh                     # Dependency installer + setup
├── requirements.txt             # Python dependencies
├── output/                      # Output JSON files
├── logs/                        # Logs and diagnostics
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
