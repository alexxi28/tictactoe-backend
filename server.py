"""
TIC×TAC×SMASH backend
- FastAPI REST + Socket.IO realtime
- MongoDB persistence (users, sessions, rooms, login_attempts)
- Custom JWT auth (email+password) AND Emergent Google auth
- Stats per user: easy/hard records + online ELO
- Realtime leaderboard broadcast
"""
import secrets
import asyncio
import os
import random
import string
import logging
import uuid
import bcrypt
import jwt
import httpx
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import socketio
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("server")

# ---------- DB ----------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# ---------- App ----------
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
fastapi_app = FastAPI(title="TIC×TAC×SMASH API")
def _allowed_origins():
    raw = os.environ.get("CORS_ORIGINS", "")
    items = [o.strip() for o in raw.split(",") if o.strip() and o.strip() != "*"]
    if not items:
        # Sensible defaults: preview URL + production domain + local dev
        items = [
            "http://localhost:3000",
            "https://tictactoeunbeatable.com",
            "https://www.tictactoeunbeatable.com",
        ]
    return items


cors_origins = _allowed_origins()
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    # Also allow any *.preview.emergentagent.com and *.emergent.host preview/prod URLs
    allow_origin_regex=r"https://.*\.(preview\.emergentagent\.com|emergent\.host)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
api = APIRouter(prefix="/api")

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALG = "HS256"
ACCESS_TTL_DAYS = 7
EMERGENT_AUTH_URL = "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data"


# ===================== AUTH HELPERS =====================
def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def make_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=ACCESS_TTL_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


async def get_user_by_id(user_id: str) -> Optional[dict]:
    u = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password_hash": 0})
    return u


async def get_current_user_optional(request: Request) -> Optional[dict]:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None
    user_id = decode_token(token)
    if not user_id:
        return None
    return await get_user_by_id(user_id)


async def get_current_user(request: Request) -> dict:
    u = await get_current_user_optional(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return u


def default_stats() -> dict:
    return {
        "easy": {"wins": 0, "losses": 0, "draws": 0, "points": 0},
        "hard": {"wins": 0, "losses": 0, "draws": 0, "points": 0},
        "online": {"wins": 0, "losses": 0, "draws": 0, "elo": 1000},
    }


# Points: +20 win, +5 draw, -8 loss (per user's spec)
POINTS_DELTA = {"win": 20, "draw": 5, "loss": -8}


def set_auth_cookie(response: Response, token: str):
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=ACCESS_TTL_DAYS * 86400,
        path="/",
    )


# ===================== AUTH MODELS =====================
class RegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str = Field(min_length=1, max_length=24)

class LoginBody(BaseModel):
    email: EmailStr
    password: str


# ===================== AUTH ENDPOINTS =====================
@api.post("/auth/register")
async def auth_register(body: RegisterBody, response: Response):
    email = body.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    doc = {
        "user_id": user_id,
        "email": email,
        "name": body.name.strip(),
        "password_hash": hash_pw(body.password),
        "provider": "password",
        "stats": default_stats(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc.copy())
    token = make_token(user_id)
    set_auth_cookie(response, token)
    return {"user_id": user_id, "email": email, "name": body.name, "stats": doc["stats"], "token": token}


@api.post("/auth/login")
async def auth_login(body: LoginBody, response: Response):
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_pw(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token(user["user_id"])
    set_auth_cookie(response, token)
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "stats": user.get("stats", default_stats()),
        "token": token,
    }


@api.post("/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@api.get("/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    user.pop("password_hash", None)
    return user


class UpdateProfileBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=24)
    picture: Optional[str] = Field(default=None, max_length=800_000)  # data URL up to ~600KB


@api.put("/auth/me")
async def auth_update_me(body: UpdateProfileBody, user: dict = Depends(get_current_user)):
    update = {}
    if body.name is not None:
        n = body.name.strip()
        if not n:
            raise HTTPException(400, "Name cannot be empty")
        update["name"] = n
    if body.picture is not None:
        pic = body.picture.strip()
        if pic == "":
            update["picture"] = None
        else:
            # Basic validation: must be a data URL with image/* MIME
            if not (pic.startswith("data:image/") and ";base64," in pic) and not pic.startswith("https://"):
                raise HTTPException(400, "Picture must be a data: image URL or https:// URL")
            update["picture"] = pic
    if not update:
        raise HTTPException(400, "Nothing to update")
    await db.users.update_one({"user_id": user["user_id"]}, {"$set": update})
    fresh = await get_user_by_id(user["user_id"])
    return fresh


# ===== Feedback form =====
SITE_OWNER_EMAIL = os.environ.get("SITE_OWNER_EMAIL", "tunbeatable@tictactoeunbeatable.com")


class FeedbackBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    message: str = Field(min_length=3, max_length=4000)
    # Honeypot — should be empty. Bots will fill it.
    website: Optional[str] = ""


@api.post("/feedback")
async def submit_feedback(body: FeedbackBody, request: Request):
    if body.website and body.website.strip():
        # Honeypot triggered → silently accept (don't tell bot it failed)
        return {"ok": True}
    doc = {
        "id": f"fb_{uuid.uuid4().hex[:12]}",
        "name": body.name.strip(),
        "email": body.email.lower().strip(),
        "message": body.message.strip(),
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:200],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.feedback.insert_one(doc.copy())
    # Notify site owner
    subject = f"New feedback from {doc['name']}"
    html = (
        f"<p><strong>{doc['name']}</strong> &lt;{doc['email']}&gt; just sent a message:</p>"
        f"<blockquote style='border-left:3px solid #ddd;padding:0 12px;margin:8px 0;'>"
        f"{doc['message'].replace(chr(10), '<br>')}"
        f"</blockquote>"
        f"<p style='color:#888;font-size:12px'>Submitted at {doc['created_at']}<br>IP: {doc['ip']}<br>UA: {doc['user_agent']}</p>"
    )
    await send_email_stub(SITE_OWNER_EMAIL, subject, html)
    return {"ok": True, "id": doc["id"]}


# ===== Password reset (STUB email — logs link to console; swap to Resend later) =====
class ForgotBody(BaseModel):
    email: EmailStr

class ResetBody(BaseModel):
    token: str
    new_password: str = Field(min_length=6)


async def send_email_stub(to: str, subject: str, body: str):
    """Stub email sender. Replace with Resend integration when RESEND_API_KEY is set."""
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        logger.info(f"[EMAIL STUB] To: {to} | Subject: {subject}\n{body}")
        return
    # Real send (when key is configured)
    try:
        import resend
        resend.api_key = api_key
        sender = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")
        await asyncio.to_thread(
            resend.Emails.send,
            {"from": sender, "to": [to], "subject": subject, "html": body},
        )
    except Exception as e:
        logger.error(f"Resend send failed, falling back to stub: {e}")
        logger.info(f"[EMAIL STUB] To: {to} | Subject: {subject}\n{body}")


@api.post("/auth/forgot-password")
async def auth_forgot(body: ForgotBody):
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email})
    # Always 200 to avoid email enumeration
    if user and user.get("password_hash"):
        token = secrets.token_urlsafe(32)
        await db.password_reset_tokens.insert_one({
            "token": token,
            "user_id": user["user_id"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "used": False,
        })
        # Use FRONTEND_URL if configured, else the canonical domain
        base = os.environ.get("FRONTEND_URL", "https://tictactoeunbeatable.com")
        link = f"{base}/reset-password?token={token}"
        await send_email_stub(
            email,
            "Reset your Tic Tac Toe Unbeatable password",
            f"<p>Hi,</p><p>Click below to reset your password (valid for 1 hour):</p><p><a href='{link}'>{link}</a></p>",
        )
    return {"ok": True, "message": "If that email exists, a reset link was sent."}


@api.post("/auth/reset-password")
async def auth_reset(body: ResetBody):
    rec = await db.password_reset_tokens.find_one({"token": body.token, "used": False}, {"_id": 0})
    if not rec:
        raise HTTPException(400, "Invalid or used token")
    expires_at = rec.get("expires_at")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Token expired")
    await db.users.update_one(
        {"user_id": rec["user_id"]},
        {"$set": {"password_hash": hash_pw(body.new_password)}},
    )
    await db.password_reset_tokens.update_one(
        {"token": body.token}, {"$set": {"used": True}}
    )
    return {"ok": True}


class EmergentCallbackBody(BaseModel):
    session_id: str


# REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
@api.post("/auth/emergent/callback")
async def auth_emergent_callback(body: EmergentCallbackBody, response: Response):
    async with httpx.AsyncClient(timeout=10) as client_http:
        r = await client_http.get(EMERGENT_AUTH_URL, headers={"X-Session-ID": body.session_id})
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid Google session")
    data = r.json()
    email = (data.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email missing from session")
    existing = await db.users.find_one({"email": email})
    if existing:
        user_id = existing["user_id"]
        update = {"name": data.get("name") or existing.get("name"), "picture": data.get("picture")}
        await db.users.update_one({"user_id": user_id}, {"$set": update})
    else:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        doc = {
            "user_id": user_id,
            "email": email,
            "name": data.get("name") or email.split("@")[0],
            "picture": data.get("picture"),
            "provider": "google",
            "stats": default_stats(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.users.insert_one(doc.copy())
    token = make_token(user_id)
    set_auth_cookie(response, token)
    user = await get_user_by_id(user_id)
    return {**(user or {}), "token": token}


# ===================== GAME LOGIC =====================
def check_win(board, sym):
    lines = []
    for i in range(3):
        lines.append([(i, 0), (i, 1), (i, 2)])
        lines.append([(0, i), (1, i), (2, i)])
    lines.append([(0, 0), (1, 1), (2, 2)])
    lines.append([(0, 2), (1, 1), (2, 0)])
    for line in lines:
        if all(board[r][c] == sym for r, c in line):
            return [[r, c] for r, c in line]
    return None

def is_draw(b):
    return all(c != " " for row in b for c in row)

def find_critical(board, sym):
    for i in range(3):
        row = [board[i][0], board[i][1], board[i][2]]
        if row.count(sym) == 2 and row.count(" ") == 1:
            return (i, row.index(" "))
    for i in range(3):
        col = [board[0][i], board[1][i], board[2][i]]
        if col.count(sym) == 2 and col.count(" ") == 1:
            return (col.index(" "), i)
    d1 = [board[0][0], board[1][1], board[2][2]]
    if d1.count(sym) == 2 and d1.count(" ") == 1:
        i = d1.index(" "); return (i, i)
    d2 = [board[0][2], board[1][1], board[2][0]]
    if d2.count(sym) == 2 and d2.count(" ") == 1:
        i = d2.index(" "); return (i, 2 - i)
    return None

def _verify_diag_corner(board):
    """If both main-diagonal corners (or anti-diagonal corners) are filled, take any free corner."""
    diag1_filled = board[0][0] != " " and board[1][1] != " " and board[2][2] != " "
    diag2_filled = board[0][2] != " " and board[1][1] != " " and board[2][0] != " "
    if diag1_filled or diag2_filled:
        corners = [(0, 0), (0, 2), (2, 0), (2, 2)]
        free_corners = [c for c in corners if board[c[0]][c[1]] == " "]
        if free_corners:
            return random.choice(free_corners)
    return None


def _verify_diag_edge(board):
    """Same diagonal-filled trigger, but pick a random free edge."""
    diag1_filled = board[0][0] != " " and board[1][1] != " " and board[2][2] != " "
    diag2_filled = board[0][2] != " " and board[1][1] != " " and board[2][0] != " "
    if diag1_filled or diag2_filled:
        edges = [(0, 1), (1, 0), (1, 2), (2, 1)]
        free_edges = [c for c in edges if board[c[0]][c[1]] == " "]
        if free_edges:
            return random.choice(free_edges)
    return None


def _pick_corner_skipping(i, j):
    corners = [(0, 0), (0, 2), (2, 0), (2, 2)]
    if (i, j) in corners:
        corners.remove((i, j))
    return random.choice(corners)


def _verif_edge(board):
    """When the human opens with an edge, pick the right counter-edge / corner."""
    edge_row = [board[1][0], board[1][2]]
    edge_row_idx = [(1, 0), (1, 2)]
    edge_col = [board[0][1], board[2][1]]
    edge_col_idx = [(0, 1), (2, 1)]
    if edge_row.count(" ") > edge_col.count(" "):
        return random.choice(edge_row_idx)
    if edge_row.count(" ") < edge_col.count(" "):
        return random.choice(edge_col_idx)
    for i in range(3):
        for j in range(3):
            row_free = [board[i][0], board[i][1], board[i][2]]
            col_free = [board[0][j], board[1][j], board[2][j]]
            if row_free.count(" ") == 3 and col_free.count(" ") == 3:
                return _pick_corner_skipping(i, j)
    return None


def hard_move(board):
    """
    Hard mode AI — bot plays as 'O', human plays as 'X'.
    Ported from the user-provided reference logic.
    """
    free = [(i, j) for i in range(3) for j in range(3) if board[i][j] == " "]
    if not free:
        return None

    # Special case: bot opens (board is empty) → pick a RANDOM position (per user request)
    if len(free) == 9:
        return random.choice(free)

    # 1) Win if possible
    win = find_critical(board, "O")
    if win:
        return win

    # 2) Block opponent
    block = find_critical(board, "X")
    if block:
        return block

    # 3) Player's first move analysis (8 free → human just played their opening)
    if len(free) == 8:
        if board[1][1] == "X":
            # Human took center → respond with a random corner
            return random.choice([(0, 0), (0, 2), (2, 0), (2, 2)])
        if board[1][0] == "X":
            return random.choice([(0, 0), (2, 0)])
        if board[0][1] == "X":
            return random.choice([(0, 0), (0, 2)])
        if board[1][2] == "X":
            return random.choice([(0, 2), (2, 2)])
        if board[2][1] == "X":
            return random.choice([(2, 0), (2, 2)])
        # Human opened with a corner → take the center

    # 4) Second-move counter on edges (7 free)
    if len(free) == 7:
        if board[1][0] == "X":
            empties = [c for c in [(0, 0), (2, 0)] if board[c[0]][c[1]] == " "]
            if empties:
                return random.choice(empties)
        if board[0][1] == "X":
            empties = [c for c in [(0, 0), (0, 2)] if board[c[0]][c[1]] == " "]
            if empties:
                return random.choice(empties)
        if board[1][2] == "X":
            empties = [c for c in [(0, 2), (2, 2)] if board[c[0]][c[1]] == " "]
            if empties:
                return random.choice(empties)
        if board[2][1] == "X":
            empties = [c for c in [(2, 0), (2, 2)] if board[c[0]][c[1]] == " "]
            if empties:
                return random.choice(empties)

    # 5) Take center if free
    if board[1][1] == " ":
        return (1, 1)

    # 6) Mid-game tactical scenarios (6 free)
    if len(free) == 6:
        # Classic "opposite corner" trap recovery
        if board[1][1] == "O" and board[0][0] == "X" and board[2][2] == " ":
            return (2, 2)
        diag2_edge = _verify_diag_edge(board)
        if board[1][1] == "O" and diag2_edge:
            return diag2_edge
        # Human played an edge after bot took center → respond carefully
        if board[1][0] == "X" or board[0][1] == "X" or board[1][2] == "X" or board[2][1] == "X":
            edge = _verif_edge(board)
            if edge:
                return edge

    # 7) Defensive: if both ends of a diagonal are filled by human, block via free corner
    diag_corner = _verify_diag_corner(board)
    if diag_corner:
        return diag_corner

    # 8) Otherwise: prefer free edges, then free corners, then anything
    edges = [(0, 1), (1, 0), (1, 2), (2, 1)]
    free_edges = [c for c in edges if board[c[0]][c[1]] == " "]
    if free_edges:
        return random.choice(free_edges)
    corners = [(0, 0), (0, 2), (2, 0), (2, 2)]
    free_corners = [c for c in corners if board[c[0]][c[1]] == " "]
    if free_corners:
        return random.choice(free_corners)
    return random.choice(free)

def easy_move(board):
    free = [(i,j) for i in range(3) for j in range(3) if board[i][j] == " "]
    if not free: return None
    # Always-random opening when bot starts (per user request)
    if len(free) == 9:
        return random.choice(free)
    if random.random() < 0.3:
        w = find_critical(board, "O")
        if w: return w
        if random.random() < 0.5:
            b = find_critical(board, "X")
            if b: return b
    return random.choice(free)


# ===================== REST GAME =====================
class MoveBody(BaseModel):
    board: List[List[str]]
    difficulty: str = "hard"

class MoveResp(BaseModel):
    board: List[List[str]]
    move: Optional[List[int]] = None
    winner: Optional[str] = None
    winning_line: Optional[List[List[int]]] = None
    draw: bool = False

@api.post("/ai/move", response_model=MoveResp)
async def ai_move(req: MoveBody):
    board = [r[:] for r in req.board]
    wx = check_win(board, "X")
    if wx: return MoveResp(board=board, winner="X", winning_line=wx)
    if is_draw(board): return MoveResp(board=board, draw=True)
    mv = easy_move(board) if req.difficulty == "easy" else hard_move(board)
    if mv is None: return MoveResp(board=board, draw=True)
    r, c = mv; board[r][c] = "O"
    wo = check_win(board, "O")
    if wo: return MoveResp(board=board, move=[r,c], winner="O", winning_line=wo)
    if is_draw(board): return MoveResp(board=board, move=[r,c], draw=True)
    return MoveResp(board=board, move=[r,c])


class GameResultBody(BaseModel):
    mode: str  # easy | hard
    result: str  # win | loss | draw

@api.post("/stats/ai-result")
async def submit_ai_result(body: GameResultBody, user: dict = Depends(get_current_user)):
    if body.mode not in ("easy", "hard") or body.result not in ("win", "loss", "draw"):
        raise HTTPException(400, "Invalid body")
    key_map = {"win": "wins", "loss": "losses", "draw": "draws"}
    inc = {
        f"stats.{body.mode}.{key_map[body.result]}": 1,
        f"stats.{body.mode}.points": POINTS_DELTA[body.result],
    }
    await db.users.update_one({"user_id": user["user_id"]}, {"$inc": inc})
    fresh = await get_user_by_id(user["user_id"])
    return fresh


@api.get("/leaderboard/mode/{mode}")
async def leaderboard_mode(mode: str, limit: int = 10):
    if mode not in ("easy", "hard"):
        raise HTTPException(400, "mode must be easy or hard")
    sort_field = f"stats.{mode}.points"
    cur = db.users.find(
        {sort_field: {"$exists": True}},
        {"_id": 0, "user_id": 1, "name": 1, "picture": 1, f"stats.{mode}": 1},
    ).sort(sort_field, -1).limit(limit)
    out = []
    async for u in cur:
        ms = u.get("stats", {}).get(mode, {})
        out.append({
            "user_id": u["user_id"],
            "name": u.get("name", "Player"),
            "picture": u.get("picture"),
            "points": ms.get("points", 0),
            "wins": ms.get("wins", 0),
            "losses": ms.get("losses", 0),
            "draws": ms.get("draws", 0),
        })
    return out


@api.get("/leaderboard/mode/{mode}/me")
async def leaderboard_mode_me(mode: str, user: dict = Depends(get_current_user)):
    if mode not in ("easy", "hard"):
        raise HTTPException(400, "mode must be easy or hard")
    me = await db.users.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not me:
        raise HTTPException(404, "Not found")
    ms = me.get("stats", {}).get(mode, {})
    my_points = ms.get("points", 0)
    higher = await db.users.count_documents({f"stats.{mode}.points": {"$gt": my_points}})
    return {
        "user_id": me["user_id"],
        "name": me.get("name", "Player"),
        "picture": me.get("picture"),
        "points": my_points,
        "wins": ms.get("wins", 0),
        "losses": ms.get("losses", 0),
        "draws": ms.get("draws", 0),
        "rank": higher + 1,
    }


@api.get("/leaderboard")
async def leaderboard(limit: int = 20):
    cur = db.users.find(
        {"stats.online.wins": {"$gte": 0}},
        {"_id": 0, "user_id": 1, "name": 1, "picture": 1, "stats.online": 1},
    ).sort("stats.online.elo", -1).limit(limit)
    out = []
    async for u in cur:
        online = u.get("stats", {}).get("online", {})
        out.append({
            "user_id": u["user_id"],
            "name": u.get("name", "Player"),
            "picture": u.get("picture"),
            "elo": online.get("elo", 1000),
            "wins": online.get("wins", 0),
            "losses": online.get("losses", 0),
            "draws": online.get("draws", 0),
        })
    return out


async def user_rank(user_id: str) -> Optional[dict]:
    me = await db.users.find_one({"user_id": user_id}, {"_id": 0, "user_id": 1, "name": 1, "picture": 1, "stats.online": 1})
    if not me:
        return None
    online = me.get("stats", {}).get("online", {})
    my_elo = online.get("elo", 1000)
    higher = await db.users.count_documents({"stats.online.elo": {"$gt": my_elo}})
    return {
        "user_id": me["user_id"],
        "name": me.get("name", "Player"),
        "picture": me.get("picture"),
        "elo": my_elo,
        "wins": online.get("wins", 0),
        "losses": online.get("losses", 0),
        "draws": online.get("draws", 0),
        "rank": higher + 1,
    }


@api.get("/leaderboard/me")
async def leaderboard_me(user: dict = Depends(get_current_user)):
    r = await user_rank(user["user_id"])
    if not r:
        raise HTTPException(404, "Not found")
    return r


fastapi_app.include_router(api)


# ===================== SOCKET.IO MULTIPLAYER =====================
def new_board():
    return [[" "]*3 for _ in range(3)]

def gen_room_code(existing) -> str:
    alphabet = string.ascii_uppercase.replace("O","").replace("I","")
    while True:
        code = "".join(random.choices(alphabet, k=5))
        if code not in existing:
            return code

# in-memory cache + mongo persistence
rooms: Dict[str, dict] = {}
sid_index: Dict[str, dict] = {}  # sid -> {room_id, symbol, user_id}
matchmaking_queue: List[dict] = []  # [{sid, name, user_id, theme, elo, queued_at}]

# ELO bracket settings
ELO_BRACKET_START = 50    # start at ±50
ELO_BRACKET_STEP = 25     # widen by ±25
ELO_BRACKET_INTERVAL = 5  # every 5 seconds


async def load_room(code: str) -> Optional[dict]:
    if code in rooms:
        return rooms[code]
    doc = await db.rooms.find_one({"room_id": code}, {"_id": 0})
    if doc:
        rooms[code] = doc
        return doc
    return None

async def save_room(code: str):
    if code in rooms:
        await db.rooms.update_one(
            {"room_id": code}, {"$set": rooms[code]}, upsert=True
        )

async def delete_room(code: str):
    rooms.pop(code, None)
    await db.rooms.delete_one({"room_id": code})


def room_state(code: str) -> dict:
    r = rooms[code]
    return {
        "room_id": code,
        "board": r["board"],
        "turn": r["turn"],
        "players": {
            "X": r["players"].get("X", {}).get("name"),
            "O": r["players"].get("O", {}).get("name"),
        },
        "scores": r["scores"],
        "status": r["status"],
        "winner": r.get("winner"),
        "winning_line": r.get("winning_line"),
        "theme": r.get("theme", "classic"),
    }


def expected_score(a, b):
    return 1 / (1 + 10 ** ((b - a) / 400))

K = 32

async def apply_elo(winner_user_id: Optional[str], loser_user_id: Optional[str], draw: bool):
    """Update ELO + online stats for both players. Either id can be None (guest)."""
    async def fetch(uid):
        if not uid: return None
        return await db.users.find_one({"user_id": uid}, {"_id": 0})

    w = await fetch(winner_user_id)
    l = await fetch(loser_user_id)
    ra = (w.get("stats", {}).get("online", {}).get("elo", 1000)) if w else 1000
    rb = (l.get("stats", {}).get("online", {}).get("elo", 1000)) if l else 1000
    ea = expected_score(ra, rb); eb = expected_score(rb, ra)
    if draw:
        new_a = ra + K * (0.5 - ea); new_b = rb + K * (0.5 - eb)
    else:
        new_a = ra + K * (1 - ea); new_b = rb + K * (0 - eb)
    if w:
        inc = {"stats.online.draws": 1} if draw else {"stats.online.wins": 1}
        await db.users.update_one(
            {"user_id": winner_user_id},
            {"$set": {"stats.online.elo": round(new_a)}, "$inc": inc},
        )
    if l:
        inc = {"stats.online.draws": 1} if draw else {"stats.online.losses": 1}
        await db.users.update_one(
            {"user_id": loser_user_id},
            {"$set": {"stats.online.elo": round(new_b)}, "$inc": inc},
        )


async def broadcast_leaderboard():
    top = await leaderboard(limit=10)
    await sio.emit("leaderboard", top)


async def remove_from_queue(sid: str):
    global matchmaking_queue
    matchmaking_queue = [q for q in matchmaking_queue if q["sid"] != sid]


async def try_match():
    """Pair queued players whose ELO brackets overlap. Brackets widen with wait time."""
    if len(matchmaking_queue) < 2:
        return
    now = datetime.now(timezone.utc).timestamp()

    def bracket(p):
        waited = max(0, now - p.get("queued_at", now))
        steps = int(waited // ELO_BRACKET_INTERVAL)
        return ELO_BRACKET_START + steps * ELO_BRACKET_STEP

    # Sort by waiting time so the oldest player gets matched first
    queue = sorted(matchmaking_queue, key=lambda p: p.get("queued_at", now))
    paired_ids = set()
    for i, p1 in enumerate(queue):
        if p1["sid"] in paired_ids:
            continue
        b1 = bracket(p1)
        # Find best partner within p1's bracket AND p2's bracket
        for p2 in queue[i + 1:]:
            if p2["sid"] in paired_ids:
                continue
            b2 = bracket(p2)
            diff = abs(p1["elo"] - p2["elo"])
            if diff <= max(b1, b2):
                paired_ids.add(p1["sid"])
                paired_ids.add(p2["sid"])
                break

    # Pop paired
    pairs = []
    if not paired_ids:
        return
    remaining = []
    pair_buffer = {}
    for p in matchmaking_queue:
        if p["sid"] in paired_ids:
            pair_buffer[p["sid"]] = p
        else:
            remaining.append(p)
    matchmaking_queue.clear()
    matchmaking_queue.extend(remaining)

    # Re-create pairs in original (waiting-time) order
    paired_list = sorted(pair_buffer.values(), key=lambda p: p.get("queued_at", now))
    for i in range(0, len(paired_list) - 1, 2):
        pairs.append((paired_list[i], paired_list[i + 1]))

    for p1, p2 in pairs:
        code = gen_room_code(rooms)
        rooms[code] = {
            "room_id": code,
            "board": new_board(),
            "turn": "X",
            "players": {
                "X": {"sid": p1["sid"], "name": p1["name"], "user_id": p1["user_id"]},
                "O": {"sid": p2["sid"], "name": p2["name"], "user_id": p2["user_id"]},
            },
            "scores": {"X": 0, "O": 0, "draws": 0},
            "status": "playing",
            "winner": None,
            "winning_line": None,
            "theme": p1.get("theme", "classic"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await save_room(code)
        for p, sym in ((p1, "X"), (p2, "O")):
            await sio.enter_room(p["sid"], code)
            sid_index[p["sid"]] = {"room_id": code, "symbol": sym, "user_id": p["user_id"]}
            await sio.emit(
                "matched",
                {"room_id": code, "symbol": sym, "opponent": (p2 if sym == "X" else p1)["name"], "opponent_elo": (p2 if sym == "X" else p1)["elo"]},
                to=p["sid"],
            )
        await sio.emit("state", room_state(code), room=code)


async def resolve_user_from_token(token: Optional[str]) -> Optional[dict]:
    if not token: return None
    uid = decode_token(token)
    if not uid: return None
    return await get_user_by_id(uid)


@sio.event
async def connect(sid, environ):
    logger.info(f"socket connected {sid}")
    top = await leaderboard(limit=10)
    await sio.emit("leaderboard", top, to=sid)


@sio.event
async def disconnect(sid):
    logger.info(f"socket disconnected {sid}")
    await remove_from_queue(sid)
    info = sid_index.pop(sid, None)
    if not info: return
    code = info["room_id"]; sym = info["symbol"]
    if code not in rooms: return
    room = rooms[code]
    if sym in room["players"] and room["players"][sym].get("sid") == sid:
        room["players"][sym] = {}
    if not room["players"].get("X") and not room["players"].get("O"):
        await delete_room(code); return
    room["status"] = "waiting"
    await save_room(code)
    await sio.emit("opponent_left", {"symbol": sym}, room=code)
    await sio.emit("state", room_state(code), room=code)


@sio.event
async def find_match(sid, data):
    """Add player to matchmaking queue, attempt to pair."""
    data = data or {}
    if sid in [q["sid"] for q in matchmaking_queue]:
        return
    user = await resolve_user_from_token(data.get("token"))
    name = (user["name"] if user else (data.get("name") or "Guest")) or "Guest"
    theme = data.get("theme", "classic")
    elo = (user.get("stats", {}).get("online", {}).get("elo", 1000)) if user else 1000
    matchmaking_queue.append({
        "sid": sid,
        "name": name,
        "user_id": user["user_id"] if user else None,
        "theme": theme,
        "elo": elo,
        "queued_at": datetime.now(timezone.utc).timestamp(),
    })
    await sio.emit("queued", {"position": len(matchmaking_queue), "elo": elo}, to=sid)
    await try_match()


# Periodic widening sweep — every 2s, retry matchmaking so brackets widen automatically
async def _matchmaking_loop():
    while True:
        try:
            await try_match()
        except Exception as e:
            logger.error(f"matchmaking loop error: {e}")
        await asyncio.sleep(2)


@sio.event
async def cancel_match(sid, data):
    await remove_from_queue(sid)
    await sio.emit("queue_cancelled", {}, to=sid)


@sio.event
async def create_room(sid, data):
    data = data or {}
    user = await resolve_user_from_token(data.get("token"))
    name = (user["name"] if user else (data.get("name") or "Player 1")) or "Player 1"
    theme = data.get("theme", "classic")
    code = gen_room_code(rooms)
    rooms[code] = {
        "room_id": code,
        "board": new_board(),
        "turn": "X",
        "players": {
            "X": {"sid": sid, "name": name, "user_id": user["user_id"] if user else None},
            "O": {},
        },
        "scores": {"X": 0, "O": 0, "draws": 0},
        "status": "waiting",
        "winner": None,
        "winning_line": None,
        "theme": theme,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await save_room(code)
    await sio.enter_room(sid, code)
    sid_index[sid] = {"room_id": code, "symbol": "X", "user_id": user["user_id"] if user else None}
    await sio.emit("room_created", {"room_id": code, "symbol": "X"}, to=sid)
    await sio.emit("state", room_state(code), room=code)


@sio.event
async def join_room(sid, data):
    data = data or {}
    code = (data.get("room_id") or "").upper().strip()
    if not code:
        await sio.emit("error_msg", {"message": "Room code required"}, to=sid); return
    room = await load_room(code)
    if not room:
        await sio.emit("error_msg", {"message": "Room not found"}, to=sid); return
    user = await resolve_user_from_token(data.get("token"))
    name = (user["name"] if user else (data.get("name") or "Player 2")) or "Player 2"
    if not room["players"].get("X"):
        sym = "X"
    elif not room["players"].get("O"):
        sym = "O"
    else:
        await sio.emit("error_msg", {"message": "Room is full"}, to=sid); return
    room["players"][sym] = {"sid": sid, "name": name, "user_id": user["user_id"] if user else None}
    if room["players"].get("X", {}).get("sid") and room["players"].get("O", {}).get("sid"):
        room["status"] = "playing"
        room["board"] = new_board()
        room["turn"] = "X"
        room["winner"] = None
        room["winning_line"] = None
    await save_room(code)
    await sio.enter_room(sid, code)
    sid_index[sid] = {"room_id": code, "symbol": sym, "user_id": user["user_id"] if user else None}
    await sio.emit("joined", {"room_id": code, "symbol": sym}, to=sid)
    await sio.emit("state", room_state(code), room=code)


@sio.event
async def make_move(sid, data):
    info = sid_index.get(sid)
    if not info: return
    code = info["room_id"]; sym = info["symbol"]
    room = rooms.get(code)
    if not room or room["status"] != "playing": return
    r, c = data.get("row"), data.get("col")
    if r is None or c is None or not (0 <= r < 3 and 0 <= c < 3): return
    if room["board"][r][c] != " " or room["turn"] != sym: return
    room["board"][r][c] = sym
    win = check_win(room["board"], sym)
    elo_changed = False
    if win:
        room["status"] = "finished"
        room["winner"] = sym
        room["winning_line"] = win
        room["scores"][sym] += 1
        # ELO update
        opp = "O" if sym == "X" else "X"
        w_uid = room["players"][sym].get("user_id")
        l_uid = room["players"][opp].get("user_id")
        await apply_elo(w_uid, l_uid, draw=False)
        elo_changed = True
    elif is_draw(room["board"]):
        room["status"] = "finished"
        room["winner"] = "draw"
        room["scores"]["draws"] += 1
        x_uid = room["players"]["X"].get("user_id")
        o_uid = room["players"]["O"].get("user_id")
        await apply_elo(x_uid, o_uid, draw=True)
        elo_changed = True
    else:
        room["turn"] = "O" if sym == "X" else "X"
    await save_room(code)
    await sio.emit("state", room_state(code), room=code)
    if elo_changed:
        await broadcast_leaderboard()


@sio.event
async def reset_board(sid, data):
    info = sid_index.get(sid)
    if not info: return
    code = info["room_id"]
    room = rooms.get(code)
    if not room: return
    room["board"] = new_board()
    room["turn"] = "X"
    room["winner"] = None
    room["winning_line"] = None
    if room["players"].get("X", {}).get("sid") and room["players"].get("O", {}).get("sid"):
        room["status"] = "playing"
    await save_room(code)
    await sio.emit("state", room_state(code), room=code)


@sio.event
async def change_theme(sid, data):
    info = sid_index.get(sid)
    if not info: return
    code = info["room_id"]
    room = rooms.get(code)
    if not room: return
    room["theme"] = (data or {}).get("theme", "classic")
    await save_room(code)
    await sio.emit("state", room_state(code), room=code)


@sio.event
async def leave_room(sid, data):
    info = sid_index.pop(sid, None)
    if not info: return
    code = info["room_id"]; sym = info["symbol"]
    room = rooms.get(code)
    if not room: return
    await sio.leave_room(sid, code)
    if sym in room["players"]:
        room["players"][sym] = {}
    if not room["players"].get("X") and not room["players"].get("O"):
        await delete_room(code); return
    room["status"] = "waiting"
    await save_room(code)
    await sio.emit("opponent_left", {"symbol": sym}, room=code)
    await sio.emit("state", room_state(code), room=code)


# ===================== STARTUP =====================
@fastapi_app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    # Start background matchmaking widening loop
    asyncio.create_task(_matchmaking_loop())
    logger.info("Indexes created + matchmaking loop running")


# Wrap FastAPI with Socket.IO
socket_app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="/api/socket.io")
app = socket_app


@fastapi_app.on_event("shutdown")
async def shutdown():
    client.close()

app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="socket.io")
