import os
from typing import Any, Dict, List, Optional
from datetime import datetime
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure

# Global database client
client: Optional[MongoClient] = None
_db = None

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "appdb")


def _connect():
    global client, _db
    if client is None:
        client = MongoClient(DATABASE_URL)
    _db = client[DATABASE_NAME]
    return _db


# Public handle to database
try:
    db = _connect()
except Exception:
    db = None


def get_collection(name: str) -> Collection:
    if db is None:
        raise ConnectionFailure("Database not initialized")
    return db[name]


def _with_timestamps(data: Dict[str, Any], is_update: bool = False) -> Dict[str, Any]:
    now = datetime.utcnow()
    if not is_update:
        data.setdefault("created_at", now)
    data["updated_at"] = now
    return data


# CRUD helpers

def create_document(collection_name: str, data: Dict[str, Any]) -> str:
    col = get_collection(collection_name)
    doc = _with_timestamps(data.copy(), is_update=False)
    result = col.insert_one(doc)
    return str(result.inserted_id)


def get_documents(collection_name: str, filter_dict: Dict[str, Any] | None = None, limit: int = 50) -> List[Dict[str, Any]]:
    col = get_collection(collection_name)
    cur = col.find(filter_dict or {}).limit(limit)
    docs = []
    for d in cur:
        d["id"] = str(d.pop("_id"))
        docs.append(d)
    return docs


def get_document_by_id(collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
    from bson import ObjectId
    col = get_collection(collection_name)
    doc = col.find_one({"_id": ObjectId(doc_id)})
    if not doc:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc


def update_document(collection_name: str, doc_id: str, data: Dict[str, Any]) -> bool:
    from bson import ObjectId
    col = get_collection(collection_name)
    payload = {"$set": _with_timestamps(data.copy(), is_update=True)}
    res = col.update_one({"_id": ObjectId(doc_id)}, payload)
    return res.modified_count > 0


def delete_document(collection_name: str, doc_id: str) -> bool:
    from bson import ObjectId
    col = get_collection(collection_name)
    res = col.delete_one({"_id": ObjectId(doc_id)})
    return res.deleted_count > 0
