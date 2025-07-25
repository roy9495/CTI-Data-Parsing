# Run with a basic demo query
import cti_processor

cti_processor.process_database(
    name="abuseipdb_blacklisted",
    query="SELECT * FROM your_table WHERE confidence > 80 LIMIT 500"
)
