import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents, get_document_by_id, update_document, delete_document

# Optional file parsers
from io import BytesIO

try:
    from pypdf import PdfReader  # lightweight PDF text extraction
except Exception:
    PdfReader = None  # type: ignore

try:
    from PIL import Image  # basic metadata for images
except Exception:
    Image = None  # type: ignore

# -------- Stdlib crypto helpers (avoid external JWT/passlib deps) --------
import hmac
import hashlib
import base64
import json

app = FastAPI(title="AI Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
http_bearer = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
TOKEN_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "43200"))  # 30 days by default


# --------------------------- Utils ---------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    iters = 200_000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_hex, dk_hex = stored.split('$')
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def create_token(sub: str, extra: Dict[str, Any] | None = None) -> str:
    payload = {"sub": sub, "exp": int((datetime.utcnow() + timedelta(minutes=TOKEN_EXP_MIN)).timestamp())}
    if extra:
        payload.update(extra)
    payload_bytes = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    sig = hmac.new(SECRET_KEY.encode('utf-8'), payload_bytes, hashlib.sha256).digest()
    return b64url_encode(payload_bytes) + "." + b64url_encode(sig)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload_b64, sig_b64 = token.split('.')
        payload_bytes = b64url_decode(payload_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(SECRET_KEY.encode('utf-8'), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=401, detail="Invalid token signature")
        data = json.loads(payload_bytes.decode('utf-8'))
        if int(data.get('exp', 0)) < int(datetime.utcnow().timestamp()):
            raise HTTPException(status_code=401, detail="Token expired")
        return data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)) -> dict:
    data = decode_token(credentials.credentials)
    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = get_document_by_id("user", user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# --------------------------- Models ---------------------------
class SignupIn(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class GoogleLoginIn(BaseModel):
    id_token: str


class ChatIn(BaseModel):
    content: str
    conversation_id: Optional[str] = None
    file_ids: Optional[List[str]] = None


class ChatOut(BaseModel):
    response: str
    conversation_id: str
    messages: List[Dict[str, Any]]


# --------------------------- Routes ---------------------------
@app.get("/")
def root():
    return {"message": "AI Assistant Backend ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["connection_status"] = "Connected"
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:60]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:60]}"
    return response


# --------------------------- Auth ---------------------------
@app.post("/auth/signup")
def signup(payload: SignupIn):
    existing = get_documents("user", {"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "provider": "password",
        "created_at": datetime.utcnow(),
        "settings": {"theme": "light"}
    }
    user_id = create_document("user", user_doc)
    token = create_token(user_id, {"email": payload.email})
    return {"token": token, "user": {"id": user_id, "name": payload.name, "email": payload.email}}


@app.post("/auth/login")
def login(payload: LoginIn):
    users = get_documents("user", {"email": payload.email})
    if not users:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    user = users[0]
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_token(user["id"], {"email": user["email"]})
    return {"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}


@app.post("/auth/google")
def google_login(payload: GoogleLoginIn):
    import requests
    resp = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": payload.id_token})
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid Google token")
    data = resp.json()
    email = data.get("email")
    name = data.get("name") or (email.split("@")[0] if email else "User")
    if not email:
        raise HTTPException(status_code=400, detail="Email missing in Google token")
    users = get_documents("user", {"email": email})
    if users:
        user = users[0]
        user_id = user["id"]
    else:
        user_id = create_document("user", {
            "name": name,
            "email": email,
            "provider": "google",
            "google_sub": data.get("sub"),
            "created_at": datetime.utcnow(),
            "settings": {"theme": "light"}
        })
    token = create_token(user_id, {"email": email})
    return {"token": token, "user": {"id": user_id, "name": name, "email": email}}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"user": {"id": user["id"], "name": user.get("name"), "email": user.get("email"), "settings": user.get("settings", {})}}


# --------------------------- Files ---------------------------
@app.post("/files/upload")
def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    filename = file.filename
    content = file.file.read()
    size = len(content)
    text_content = None
    meta: Dict[str, Any] = {"filename": filename, "size": size, "content_type": file.content_type}

    # Try to extract text
    ext = (filename or "").lower().split('.')[-1]
    if ext in ["txt", "md"]:
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except Exception:
            text_content = None
    elif ext in ["pdf"] and PdfReader is not None:
        try:
            reader = PdfReader(BytesIO(content))
            chunks = []
            for page in reader.pages:
                try:
                    chunks.append(page.extract_text() or "")
                except Exception:
                    pass
            text_content = "\n".join(chunks).strip() or None
        except Exception:
            text_content = None
    elif ext in ["jpg", "jpeg", "png"] and Image is not None:
        try:
            img = Image.open(BytesIO(content))
            meta["image"] = {"mode": img.mode, "size": img.size}
        except Exception:
            pass

    file_doc = {
        "user_id": user["id"],
        "filename": filename,
        "content_type": file.content_type,
        "size": size,
        "text": text_content,
        "uploaded_at": datetime.utcnow(),
        "meta": meta,
    }
    file_id = create_document("files", file_doc)
    return {"file_id": file_id, "text_preview": (text_content[:500] if text_content else None)}


# --------------------------- Chat ---------------------------

def simple_ai_respond(prompt: str, attached_texts: Optional[List[str]] = None) -> str:
    base = prompt.strip()
    context = "\n\n".join(attached_texts or [])
    if context and any(k in base.lower() for k in ["summarize", "summary", "tl;dr"]):
        txt = context[:2000]
        sentences = [s.strip() for s in txt.replace("\n", " ").split(".") if s.strip()]
        summary = ". ".join(sentences[:3])
        return f"Here is a concise summary based on the uploaded file(s):\n- {summary}"
    if context:
        return f"I reviewed your prompt and the attached content. Here are useful insights:\n- Prompt: {base[:300]}\n- Attached context length: {len(context)} characters\n\nSuggestion: Ask me to 'summarize' or 'extract key points' for focused results."
    return (
        "Got it! I'm your AI assistant. I can help with Q&A, explanations, summaries, and creative ideas. "
        "Provide more details for better results, or attach a file for analysis."
    )


@app.post("/chat", response_model=ChatOut)
def chat(payload: ChatIn, user: dict = Depends(get_current_user)):
    attached_texts: List[str] = []
    for fid in payload.file_ids or []:
        file_docs = get_documents("files", {"id": fid, "user_id": user["id"]})
        if file_docs and file_docs[0].get("text"):
            attached_texts.append(file_docs[0]["text"])    

    assistant = simple_ai_respond(payload.content, attached_texts=attached_texts)

    conversations = None
    convo_id = payload.conversation_id
    if convo_id:
        conversations = get_documents("conversations", {"id": convo_id, "user_id": user["id"]})
    if conversations:
        convo = conversations[0]
        messages = convo.get("messages", [])
        messages.append({"role": "user", "content": payload.content, "ts": datetime.utcnow()})
        messages.append({"role": "assistant", "content": assistant, "ts": datetime.utcnow()})
        update_document("conversations", convo["id"], {"messages": messages, "updated_at": datetime.utcnow()})
        conversation_id = convo["id"]
    else:
        conversation_id = create_document("conversations", {
            "user_id": user["id"],
            "title": payload.content[:60] if payload.content else "New Chat",
            "messages": [
                {"role": "user", "content": payload.content, "ts": datetime.utcnow()},
                {"role": "assistant", "content": assistant, "ts": datetime.utcnow()},
            ],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })

    convo = get_documents("conversations", {"id": conversation_id})[0]
    return ChatOut(response=assistant, conversation_id=conversation_id, messages=convo.get("messages", []))


@app.get("/conversations")
def list_conversations(user: dict = Depends(get_current_user)):
    convos = get_documents("conversations", {"user_id": user["id"]}, limit=100)
    for c in convos:
        c.pop("messages", None)
    return {"items": convos}


@app.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, user: dict = Depends(get_current_user)):
    convos = get_documents("conversations", {"id": conversation_id, "user_id": user["id"]})
    if not convos:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return convos[0]


@app.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, user: dict = Depends(get_current_user)):
    convos = get_documents("conversations", {"id": conversation_id, "user_id": user["id"]})
    if not convos:
        raise HTTPException(status_code=404, detail="Conversation not found")
    ok = delete_document("conversations", conversation_id)
    return {"deleted": ok}


@app.post("/conversations/clear")
def clear_conversations(user: dict = Depends(get_current_user)):
    convos = get_documents("conversations", {"user_id": user["id"]}, limit=1000)
    count = 0
    for c in convos:
        if delete_document("conversations", c["id"]):
            count += 1
    return {"cleared": count}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
