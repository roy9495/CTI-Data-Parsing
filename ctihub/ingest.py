import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ctihub.models import StixObject, StixRelationship

def extract_indicator_value(pattern):
    # Quick helper to extract value from pattern like [ipv4-addr:value = '1.1.1.1']
    if not pattern:
        return ""
    try:
        if "value =" in pattern:
            parts = pattern.split("value =")
            if len(parts) > 1:
                val = parts[1].strip().strip("']").strip("'")
                return val
    except Exception:
        pass
    return pattern

def ingest_stix_bundle(db: Session, bundle_dict: dict, source_name: str = None) -> int:
    """
    Ingests a STIX 2.1 Bundle dictionary into the SQLite database.
    Returns the number of ingested/processed objects.
    """
    objects = bundle_dict.get("objects", [])
    count = 0

    for obj in objects:
        obj_id = obj.get("id")
        obj_type = obj.get("type")

        if not obj_id or not obj_type:
            continue

        if obj_type == "relationship":
            # Process relationship
            rel_type = obj.get("relationship_type")
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")

            if not rel_type or not source_ref or not target_ref:
                continue

            existing_rel = db.query(StixRelationship).filter(StixRelationship.id == obj_id).first()
            if existing_rel:
                existing_rel.relationship_type = rel_type
                existing_rel.source_ref = source_ref
                existing_rel.target_ref = target_ref
                existing_rel.description = obj.get("description")
                existing_rel.stix_json = json.dumps(obj)
                existing_rel.source = source_name or obj.get("x_source_platform")
            else:
                new_rel = StixRelationship(
                    id=obj_id,
                    relationship_type=rel_type,
                    source_ref=source_ref,
                    target_ref=target_ref,
                    description=obj.get("description"),
                    stix_json=json.dumps(obj),
                    source=source_name or obj.get("x_source_platform")
                )
                db.add(new_rel)
            count += 1
        else:
            # Process SDO
            name = obj.get("name")
            if not name:
                if obj_type == "indicator":
                    name = obj.get("x_ioc_value") or extract_indicator_value(obj.get("pattern"))
                elif obj_type == "vulnerability":
                    name = obj.get("external_references", [{}])[0].get("external_id") or obj_id
                else:
                    name = obj_id

            confidence = obj.get("confidence", 70)
            description = obj.get("description")

            existing_obj = db.query(StixObject).filter(StixObject.id == obj_id).first()
            if existing_obj:
                existing_obj.type = obj_type
                existing_obj.name = name
                existing_obj.description = description
                existing_obj.confidence = confidence
                existing_obj.stix_json = json.dumps(obj)
                existing_obj.source = source_name or obj.get("x_source_platform") or existing_obj.source
                existing_obj.updated_at = datetime.now(timezone.utc)
            else:
                new_obj = StixObject(
                    id=obj_id,
                    type=obj_type,
                    name=name,
                    description=description,
                    confidence=confidence,
                    stix_json=json.dumps(obj),
                    source=source_name or obj.get("x_source_platform")
                )
                db.add(new_obj)
            count += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[X] Error committing STIX bundle ingestion: {e}")
        raise e

    return count
