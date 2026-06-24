import os
import json
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from ctihub.database import init_db, get_db
from ctihub.models import StixObject, StixRelationship, Connector
from ctihub.connectors import register_connectors_if_missing, trigger_connector_run
from ctihub.ingest import ingest_stix_bundle

app = FastAPI(
    title="CTIHub Platform",
    description="A Cyber Threat Intelligence platform based on STIX 2.1 and standard connectors.",
    version="1.0.0"
)

startup_error_message = None

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup Error Middleware
@app.middleware("http")
async def check_startup_error(request, call_next):
    global startup_error_message
    # Bypass middleware check for the environment debugger
    if request.url.path == "/api/debug-env":
        return await call_next(request)
        
    if startup_error_message:
        from fastapi.responses import HTMLResponse
        html_content = f"""
        <html>
            <head><title>CTIHub Startup Debugger</title></head>
            <body style="font-family: monospace; padding: 20px; background: #1a1a1a; color: #ff5555; line-height: 1.5;">
                <h1 style="color: #ff3333; border-bottom: 1px solid #ff3333; padding-bottom: 10px;">Critical Startup/Initialization Error</h1>
                <p>The application started but failed to initialize correctly. Below is the traceback:</p>
                <pre style="background: #2a2a2a; padding: 15px; border-radius: 5px; overflow-x: auto; color: #f8f8f2;">{startup_error_message}</pre>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=500)
    return await call_next(request)

# Secure Environment Debug Endpoint
@app.get("/api/debug-env")
def debug_env():
    import os
    from urllib.parse import urlparse, parse_qs
    res = {}
    keys = ["DATABASE_URL", "POSTGRES_URL", "POSTGRES_URL_NON_POOLING", "SUPABASE_URL", "VERCEL", "VERCEL_ENV"]
    for key in keys:
        val = os.environ.get(key)
        if val:
            # Mask value to prevent security leaks
            parts = val.split("://")
            scheme = parts[0] if len(parts) > 1 else "no_scheme"
            
            # Parse URL parts safely
            parsed_url = None
            query_params = {}
            if scheme in ["postgres", "postgresql", "http", "https"]:
                try:
                    parsed_url = urlparse(val)
                    if parsed_url.query:
                        query_params = parse_qs(parsed_url.query)
                except Exception:
                    pass
            
            res[key] = {
                "length": len(val),
                "scheme": scheme,
                "has_spaces": " " in val,
                "has_newlines": "\n" in val or "\r" in val,
                "hostname": parsed_url.hostname if parsed_url else "N/A",
                "port": parsed_url.port if parsed_url else "N/A",
                "path": parsed_url.path if parsed_url else "N/A",
                "query_params": list(query_params.keys()) if query_params else [],
                "raw_query_masked": parsed_url.query[:30] + "..." if parsed_url and parsed_url.query else "N/A"
            }
        else:
            res[key] = "not_set"
    return res



# Initialize DB on startup
@app.on_event("startup")
def on_startup():
    global startup_error_message
    try:
        init_db()
        db = next(get_db())
        register_connectors_if_missing(db)
    except Exception as e:
        import traceback
        import sys
        startup_error_message = traceback.format_exc()
        print("!!! CRITICAL STARTUP EXCEPTION !!!", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)



# Dashboard Stats API
@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    # Counts
    total_indicators = db.query(StixObject).filter(StixObject.type == "indicator").count()
    total_malware = db.query(StixObject).filter(StixObject.type == "malware").count()
    total_actors = db.query(StixObject).filter(StixObject.type == "threat-actor").count()
    total_campaigns = db.query(StixObject).filter(StixObject.type == "campaign").count()
    total_vulns = db.query(StixObject).filter(StixObject.type == "vulnerability").count()
    total_tools = db.query(StixObject).filter(StixObject.type == "tool").count()
    total_techniques = db.query(StixObject).filter(StixObject.type == "attack-pattern").count()
    total_identities = db.query(StixObject).filter(StixObject.type == "identity").count()
    total_relationships = db.query(StixRelationship).count()
    
    total_connectors = db.query(Connector).count()
    active_connectors = db.query(Connector).filter(Connector.status == "RUNNING").count()

    # Ingestion breakdown by type
    types_breakdown = {}
    for obj_type in ["indicator", "malware", "threat-actor", "campaign", "vulnerability", "tool", "attack-pattern", "identity"]:
        count = db.query(StixObject).filter(StixObject.type == obj_type).count()
        if count > 0:
            types_breakdown[obj_type] = count

    # Source breakdown
    sources_breakdown = {}
    objects = db.query(StixObject.source).all()
    for obj in objects:
        src = obj[0] or "Unknown"
        sources_breakdown[src] = sources_breakdown.get(src, 0) + 1

    # Confidence distribution
    confidence_dist = {"high": 0, "medium": 0, "low": 0}
    all_objs = db.query(StixObject.confidence).all()
    for (conf,) in all_objs:
        if conf is None:
            conf = 70
        if conf > 80:
            confidence_dist["high"] += 1
        elif conf > 50:
            confidence_dist["medium"] += 1
        else:
            confidence_dist["low"] += 1

    return {
        "summary": {
            "indicators": total_indicators,
            "malware": total_malware,
            "threat_actors": total_actors,
            "campaigns": total_campaigns,
            "vulnerabilities": total_vulns,
            "tools": total_tools,
            "techniques": total_techniques,
            "identities": total_identities,
            "relationships": total_relationships,
            "connectors": total_connectors,
            "active_connectors": active_connectors
        },
        "breakdown": {
            "types": types_breakdown,
            "sources": sources_breakdown,
            "confidence": confidence_dist
        }
    }

# Connectors API
@app.get("/api/connectors")
def get_connectors(db: Session = Depends(get_db)):
    connectors = db.query(Connector).all()
    return connectors

# Trigger Connector
@app.post("/api/connectors/{connector_id}/trigger")
def trigger_connector(connector_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    connector = db.query(Connector).filter(Connector.id == connector_id).first()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    if connector.status == "RUNNING":
        return {"status": "already_running", "message": "Connector is already running"}

    # Set status to running immediately
    connector.status = "RUNNING"
    db.commit()

    # Add background task
    def run_task():
        # Create a new DB session for background task execution
        from ctihub.database import SessionLocal
        bg_db = SessionLocal()
        try:
            trigger_connector_run(bg_db, connector_id)
        finally:
            bg_db.close()

    background_tasks.add_task(run_task)
    return {"status": "triggered", "message": f"Connector {connector_id} run started in background"}

# Raw Ingestion Endpoint
@app.post("/api/ingest")
async def ingest_bundle(bundle: dict, db: Session = Depends(get_db)):
    try:
        count = ingest_stix_bundle(db, bundle, "Direct API Ingest")
        return {"status": "success", "ingested_objects": count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to ingest bundle: {e}")

# Indicators Search/List API
@app.get("/api/indicators")
def get_indicators(q: str = None, type: str = None, source: str = None, db: Session = Depends(get_db)):
    query = db.query(StixObject).filter(StixObject.type == "indicator")
    
    if type:
        # Match indicator sub-type via x_ioc_type
        query = query.filter(StixObject.stix_json.contains(f'"x_ioc_type": "{type}"'))
    if source:
        query = query.filter(StixObject.source == source)
    if q:
        query = query.filter(StixObject.name.contains(q) | StixObject.description.contains(q))

    indicators = query.order_by(StixObject.created_at.desc()).all()
    
    result = []
    for ind in indicators:
        try:
            stix_data = json.loads(ind.stix_json)
        except:
            stix_data = {}
        result.append({
            "id": ind.id,
            "name": ind.name,
            "description": ind.description,
            "confidence": ind.confidence,
            "source": ind.source,
            "created_at": ind.created_at,
            "ioc_type": stix_data.get("x_ioc_type", "ipv4-addr"),
            "pattern": stix_data.get("pattern", ""),
            "raw": stix_data
        })
    return result

# Threats / Objects List API
@app.get("/api/objects")
def get_objects(type: str = None, db: Session = Depends(get_db)):
    query = db.query(StixObject)
    if type:
        query = query.filter(StixObject.type == type)
    else:
        query = query.filter(StixObject.type != "indicator")
        
    objects = query.order_by(StixObject.type.asc(), StixObject.name.asc()).all()
    
    result = []
    for obj in objects:
        try:
            stix_data = json.loads(obj.stix_json)
        except:
            stix_data = {}
        result.append({
            "id": obj.id,
            "type": obj.type,
            "name": obj.name,
            "description": obj.description,
            "confidence": obj.confidence,
            "source": obj.source,
            "created_at": obj.created_at,
            "raw": stix_data
        })
    return result

# Specific Object Details
@app.get("/api/objects/{obj_id}")
def get_object_detail(obj_id: str, db: Session = Depends(get_db)):
    obj = db.query(StixObject).filter(StixObject.id == obj_id).first()
    if not obj:
        # Check in relationships
        rel = db.query(StixRelationship).filter(StixRelationship.id == obj_id).first()
        if rel:
            try:
                stix_data = json.loads(rel.stix_json)
            except:
                stix_data = {}
            return {
                "id": rel.id,
                "type": "relationship",
                "relationship_type": rel.relationship_type,
                "source_ref": rel.source_ref,
                "target_ref": rel.target_ref,
                "description": rel.description,
                "confidence": rel.confidence or 70,
                "source": rel.source,
                "raw": stix_data
            }
        raise HTTPException(status_code=404, detail="Object not found")
        
    try:
        stix_data = json.loads(obj.stix_json)
    except:
        stix_data = {}
        
    return {
        "id": obj.id,
        "type": obj.type,
        "name": obj.name,
        "description": obj.description,
        "confidence": obj.confidence,
        "source": obj.source,
        "created_at": obj.created_at,
        "raw": stix_data
    }

# Relationships / Graph Data API
@app.get("/api/relationships")
def get_relationships(db: Session = Depends(get_db)):
    relationships = db.query(StixRelationship).all()
    
    # Collect all node IDs referenced in relationships
    node_ids = set()
    for rel in relationships:
        node_ids.add(rel.source_ref)
        node_ids.add(rel.target_ref)
        
    # Get all nodes that are referenced or are of threat/actor type to populate graph
    nodes = db.query(StixObject).filter((StixObject.id.in_(list(node_ids))) | (StixObject.type.in_(["threat-actor", "malware", "campaign"]))).all()
    
    nodes_data = []
    for node in nodes:
        nodes_data.append({
            "id": node.id,
            "name": node.name,
            "type": node.type,
            "confidence": node.confidence
        })
        
    edges_data = []
    for rel in relationships:
        edges_data.append({
            "id": rel.id,
            "source": rel.source_ref,
            "target": rel.target_ref,
            "label": rel.relationship_type,
            "description": rel.description
        })
        
    return {
        "nodes": nodes_data,
        "edges": edges_data
    }

# Object Specific Relationships API
@app.get("/api/objects/{obj_id}/relationships")
def get_object_relationships(obj_id: str, db: Session = Depends(get_db)):
    relationships = db.query(StixRelationship).filter(
        (StixRelationship.source_ref == obj_id) | (StixRelationship.target_ref == obj_id)
    ).all()
    
    result = []
    for rel in relationships:
        other_ref = rel.target_ref if rel.source_ref == obj_id else rel.source_ref
        direction = "out" if rel.source_ref == obj_id else "in"
        
        other_obj = db.query(StixObject).filter(StixObject.id == other_ref).first()
        other_name = other_obj.name if other_obj else other_ref
        other_type = other_obj.type if other_obj else "unknown"
        
        result.append({
            "id": rel.id,
            "relationship_type": rel.relationship_type,
            "source_ref": rel.source_ref,
            "target_ref": rel.target_ref,
            "description": rel.description,
            "confidence": rel.confidence or 70,
            "other_id": other_ref,
            "other_name": other_name,
            "other_type": other_type,
            "direction": direction
        })
    return result

# Serve Single Page App
# Map static folder first, then return index.html for root path (only when not running on Vercel)
if not os.environ.get("VERCEL"):
    ui_dir = os.path.join(os.path.dirname(__file__), "ui")
    if not os.path.exists(ui_dir):
        os.makedirs(ui_dir, exist_ok=True)

    app.mount("/static", StaticFiles(directory=ui_dir), name="static")

    @app.get("/")
    def get_index():
        index_file = os.path.join(ui_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse(content={"message": "Welcome to CTIHub API. Frontend UI code is missing at ctihub/ui/index.html"}, status_code=200)

