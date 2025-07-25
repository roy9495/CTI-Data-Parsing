import argparse
import pandas as pd
import os
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from fuzzywuzzy import fuzz

from config.query_config import QUERY_MAP
from config.database_config import DATABASES
from transformer.database_manager import get_connection
from transformer.stix_transformer import create_stix_bundle

# -- UTIL: Fuzzy match column names to normalize
def normalize_dataframe(df):
    def fuzzy_match(col, candidates):
        match_scores = {c: fuzz.partial_ratio(col.lower(), c.lower()) for c in candidates}
        best_match = max(match_scores, key=match_scores.get)
        return best_match if match_scores[best_match] >= 70 else None

    ioc_col, conf_col = None, None
    for col in df.columns:
        if not ioc_col and fuzzy_match(col, ["ioc", "ip", "ip_address", "indicator", "domain", "url", "address", "host", "observable"]):
            ioc_col = col
        if not conf_col and fuzzy_match(col, ["confidence", "score", "threat_score", "confidence_score", "abuse_confidence_score"]):
            conf_col = col

    if not ioc_col:
        raise ValueError(f"[X] Unable to detect IOC column from: {list(df.columns)}")
    if not conf_col:
        print(f"[!] Warning: Confidence column not found, defaulting to 70.")
        df['confidence'] = 70
        conf_col = 'confidence'

    # Normalize column names
    df = df.rename(columns={ioc_col: 'ioc', conf_col: 'confidence'})
    return df[['ioc', 'confidence']]

# -- UTIL: Deduplicate IOCs with fuzzy matching
def deduplicate_iocs(df):
    seen = {}
    deduped = []

    for _, row in df.iterrows():
        ioc = str(row['ioc']).strip().lower()

        is_duplicate = False
        for existing in seen:
            if fuzz.ratio(existing, ioc) >= 95:
                is_duplicate = True
                break

        if not is_duplicate:
            seen[ioc] = True
            deduped.append(row)

    return pd.DataFrame(deduped)

def process_database(name, query):
    conn = get_connection(name)
    if not conn:
        return

    df = pd.read_sql_query(query, conn)
    if df.empty:
        print(f"[!] {name} returned no data.")
        return

    try:
        df = normalize_dataframe(df)
    except Exception as e:
        print(f"[X] {name} normalization failed: {e}")
        return

    df = deduplicate_iocs(df)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    os.makedirs("output", exist_ok=True)

    # Create STIX bundle
    stix_bundle = create_stix_bundle(df.to_dict(orient="records"), name)
    with open(f"output/stix_{name}_{timestamp}.json", "w") as f:
        f.write(str(stix_bundle))

    # Build LLM-ready output
    llm_ready = {
        "intelligence_summary": {
            "source_platform": name,
            "total_indicators": len(df),
            "confidence_distribution": {
                "high_confidence_count": int((df['confidence'] > 80).sum()),
                "medium_confidence_count": int(((df['confidence'] <= 80) & (df['confidence'] > 50)).sum()),
                "low_confidence_count": int((df['confidence'] <= 50).sum())
            }
        },
        "threat_indicators": [
            {
                "indicator_value": row['ioc'],
                "indicator_type": "ipv4-addr",  # Still static for now
                "confidence_score": int(row['confidence']),
                "confidence_assessment": (
                    "high" if row['confidence'] > 80 else
                    "medium" if row['confidence'] > 50 else
                    "low"
                ),
                "threat_labels": ["malicious-activity"],
                "source_platform": name
            } for _, row in df.iterrows()
        ]
    }

    with open(f"output/llm_ready_{name}_{timestamp}.json", "w") as f:
        json.dump(llm_ready, f, indent=2)

    print(f"[✓] Processed {name}: {len(df)} unique indicators saved.")

def run_parallel_queries():
    def task(db_name, query):
        try:
            process_database(db_name, query)
        except Exception as e:
            print(f"[X] Failed processing {db_name}: {e}")

    with ThreadPoolExecutor(max_workers=13) as executor:
        for db_name, query in QUERY_MAP.items():
            if db_name in DATABASES:
                executor.submit(task, db_name, query)
            else:
                print(f"[!] Skipping {db_name} — no DB config")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Process all databases")
    parser.add_argument("-d", "--database", help="Database name")
    parser.add_argument("-q", "--query", help="SQL query string")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        for name in DATABASES:
            get_connection(name)
    elif args.all:
        run_parallel_queries()
    elif args.database and args.query:
        process_database(args.database, args.query)
    else:
        print("[!] Invalid usage. Use --all or -d and -q.")
