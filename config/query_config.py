QUERY_MAP = {
    "abuseipdb_blacklisted": "SELECT * FROM abuseipdb_blacklist ORDER BY inserted_at desc LIMIT 1000;",
    "threatfox_ip": "SELECT * FROM threatfox_iocs ORDER BY first_seen desc LIMIT 1000;",
}