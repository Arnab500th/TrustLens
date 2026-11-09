# backend/db.py
# Persistence layer supporting MongoDB Atlas (Cloud) with graceful local fallback.
import json
import logging
import os
import sqlite3
from typing import Optional

logger = logging.getLogger("trustlens.db")

# Load dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MONGODB_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI")
_mongo_client = None
_mongo_db = None
_use_mongo = False

def init_mongo() -> bool:
    global _mongo_client, _mongo_db, _use_mongo
    if not MONGODB_URI:
        _use_mongo = False
        return False
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=4000)
        # Test connection with ping
        client.admin.command("ping")
        # Extract database name or default to 'trustlens'
        default_db = "trustlens"
        try:
            parsed_db = client.get_default_database()
            db_name = parsed_db.name if parsed_db else default_db
        except Exception:
            db_name = default_db
        _mongo_client = client
        _mongo_db = client[db_name]
        # Ensure indexes
        _mongo_db.scans.create_index("scan_id", unique=True)
        _mongo_db.scans.create_index([("checked_at", -1)])
        _mongo_db.reports.create_index([("id", -1)])
        _use_mongo = True
        logger.info(f"Connected to MongoDB Atlas: database '{db_name}'")
        return True
    except Exception as e:
        logger.warning(f"MongoDB connection failed ({e}). Falling back to SQLite.")
        _use_mongo = False
        return False


def get_db_path() -> str:
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustlens.db")
    return os.getenv("DB_PATH", default_path)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    # Try MongoDB first
    if init_mongo():
        return

    # Fallback SQLite setup
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                label TEXT NOT NULL,
                score INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                url TEXT,
                host TEXT,
                label TEXT,
                score INTEGER,
                note TEXT,
                report_hash TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


# Auto-initialize database on import
init_db()


def save_scan(result: dict) -> None:
    scan_id = result.get("scan_id", "")
    url = result.get("url", "")
    host = result.get("host", "")
    label = result.get("label", result.get("verdict", "Inconclusive"))
    score = int(result.get("score", result.get("risk_score", 0)))
    checked_at = result.get("checked_at", "") or result.get("created_at", "")

    if _use_mongo and _mongo_db is not None:
        try:
            doc = dict(result)
            doc["scan_id"] = scan_id
            doc["url"] = url
            doc["host"] = host
            doc["label"] = label
            doc["score"] = score
            doc["checked_at"] = checked_at
            _mongo_db.scans.update_one(
                {"scan_id": scan_id},
                {"$set": doc},
                upsert=True
            )
            return
        except Exception as e:
            logger.error(f"Mongo save_scan failed: {e}. Writing to SQLite.")

    # SQLite fallback
    result_json = json.dumps(result)
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO scans (scan_id, url, host, label, score, checked_at, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, url, host, label, score, checked_at, result_json))
        conn.commit()


def get_scan(scan_id: str) -> Optional[dict]:
    if _use_mongo and _mongo_db is not None:
        try:
            doc = _mongo_db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
            if doc:
                return doc
        except Exception as e:
            logger.error(f"Mongo get_scan failed: {e}")

    with get_connection() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row:
            try:
                return json.loads(row["result_json"])
            except Exception:
                return None
    return None


def find_cached_scan(url: str, host: str = "") -> Optional[dict]:
    """Finds an existing scan result for this URL or host in the database to enable instant replay."""
    if _use_mongo and _mongo_db is not None:
        try:
            query = {"$or": [{"url": url}]}
            if host:
                query["$or"].append({"host": host})
            doc = _mongo_db.scans.find_one(query, {"_id": 0}, sort=[("checked_at", -1)])
            if doc:
                return doc
        except Exception as e:
            logger.error(f"Mongo find_cached_scan failed: {e}")

    with get_connection() as conn:
        row = conn.execute("""
            SELECT result_json FROM scans 
            WHERE url = ? OR host = ? 
            ORDER BY checked_at DESC LIMIT 1
        """, (url, host or "")).fetchone()
        if row:
            try:
                return json.loads(row["result_json"])
            except Exception:
                return None
    return None


def list_scans(limit: int = 200) -> list[dict]:
    if _use_mongo and _mongo_db is not None:
        try:
            cursor = _mongo_db.scans.find({}, {"_id": 0}).sort("checked_at", -1).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Mongo list_scans failed: {e}")

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT result_json FROM scans ORDER BY checked_at DESC LIMIT ?
        """, (limit,)).fetchall()
        scans = []
        for r in rows:
            try:
                scans.append(json.loads(r["result_json"]))
            except Exception:
                pass
        return scans


def save_report(url: str, note: str = "", scan_id: str = None) -> dict:
    from datetime import datetime, timezone
    import hashlib

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_hash = "0x" + hashlib.sha256(f"{url}|{created_at}".encode("utf-8")).hexdigest()

    host = ""
    label = "Reported"
    score = 50

    if scan_id:
        scan = get_scan(scan_id)
        if scan:
            host = scan.get("host", "")
            label = scan.get("label", "Reported")
            score = scan.get("score", 50)

    if _use_mongo and _mongo_db is not None:
        try:
            count = _mongo_db.reports.count_documents({})
            report_doc = {
                "id": count + 1,
                "scan_id": scan_id or "",
                "url": url,
                "host": host,
                "label": label,
                "score": score,
                "note": note,
                "report_hash": report_hash,
                "created_at": created_at
            }
            res = _mongo_db.reports.insert_one(report_doc)
            return {
                "report_id": count + 1,
                "scan_id": scan_id,
                "url": url,
                "note": note,
                "report_hash": report_hash,
                "created_at": created_at
            }
        except Exception as e:
            logger.error(f"Mongo save_report failed: {e}")

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO reports (scan_id, url, host, label, score, note, report_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id or "", url, host, label, score, note, report_hash, created_at))
        conn.commit()
        report_id = cursor.lastrowid

    return {
        "report_id": report_id,
        "scan_id": scan_id,
        "url": url,
        "note": note,
        "report_hash": report_hash,
        "created_at": created_at
    }


def list_reports(limit: int = 50) -> list[dict]:
    if _use_mongo and _mongo_db is not None:
        try:
            cursor = _mongo_db.reports.find({}, {"_id": 0}).sort("id", -1).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Mongo list_reports failed: {e}")

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, scan_id, url, host, label, score, note, report_hash, created_at
            FROM reports ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    import tempfile
    os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test_trustlens.db")
    init_db()
    save_scan({"scan_id": "test-1", "url": "https://example.com", "host": "example.com", "label": "Low Risk", "score": 10})
    s = get_scan("test-1")
    print("saved scan:", s)
    rep = save_report("https://example.com", "Testing community report", "test-1")
    print("saved report:", rep)
    print("PASS" if s and s.get("score") == 10 and rep.get("report_id") else "FAIL")
