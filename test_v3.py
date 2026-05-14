"""v3 backend tests: points-based leaderboard (easy/hard), forgot/reset password flow."""
import os
import uuid
import asyncio
import pytest
import requests
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
BASE_URL = os.environ['REACT_APP_BACKEND_URL'].rstrip('/')
MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
PASS = "Password123!"


def _register(email, name="V3User"):
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/register",
               json={"email": email, "password": PASS, "name": name}, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["token"], s


# ===== Points system =====
def test_points_win_draw_loss_applied():
    email = f"test_pts_{uuid.uuid4().hex[:8]}@example.com"
    tok, _ = _register(email, "PointsHero")
    h = {"Authorization": f"Bearer {tok}"}

    # win on hard: +20
    r = requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "hard", "result": "win"}, headers=h, timeout=15)
    assert r.status_code == 200
    assert r.json()["stats"]["hard"]["points"] == 20
    assert r.json()["stats"]["hard"]["wins"] == 1

    # draw: +5 → 25
    r = requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "hard", "result": "draw"}, headers=h, timeout=15)
    assert r.json()["stats"]["hard"]["points"] == 25
    assert r.json()["stats"]["hard"]["draws"] == 1

    # loss: -8 → 17
    r = requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "hard", "result": "loss"}, headers=h, timeout=15)
    assert r.json()["stats"]["hard"]["points"] == 17
    assert r.json()["stats"]["hard"]["losses"] == 1

    # easy independent
    r = requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "easy", "result": "win"}, headers=h, timeout=15)
    assert r.json()["stats"]["easy"]["points"] == 20

    # GET /me consistent
    me = requests.get(f"{BASE_URL}/api/auth/me", headers=h, timeout=15).json()
    assert me["stats"]["hard"]["points"] == 17
    assert me["stats"]["easy"]["points"] == 20


# ===== Mode leaderboards =====
def test_leaderboard_mode_easy_and_hard():
    # Seed two users with different easy points
    e1 = f"test_lb_e1_{uuid.uuid4().hex[:6]}@example.com"
    e2 = f"test_lb_e2_{uuid.uuid4().hex[:6]}@example.com"
    t1, _ = _register(e1, "LBeasy1")
    t2, _ = _register(e2, "LBeasy2")
    for _ in range(3):
        requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "easy", "result": "win"},
                      headers={"Authorization": f"Bearer {t1}"}, timeout=15)
    requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "easy", "result": "win"},
                  headers={"Authorization": f"Bearer {t2}"}, timeout=15)

    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/easy", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) > 0
    pts = [u["points"] for u in data]
    assert pts == sorted(pts, reverse=True)
    for u in data:
        for k in ("user_id", "name", "points", "wins", "losses", "draws"):
            assert k in u

    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/hard", timeout=15)
    assert r.status_code == 200


def test_leaderboard_mode_invalid_400():
    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/invalid", timeout=15)
    assert r.status_code == 400


def test_leaderboard_mode_me_rank():
    email = f"test_lbme_{uuid.uuid4().hex[:6]}@example.com"
    tok, _ = _register(email, "LBme")
    h = {"Authorization": f"Bearer {tok}"}
    requests.post(f"{BASE_URL}/api/stats/ai-result", json={"mode": "hard", "result": "win"}, headers=h, timeout=15)

    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/hard/me", headers=h, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert body["points"] == 20
    assert body["wins"] == 1
    assert isinstance(body["rank"], int) and body["rank"] >= 1


def test_leaderboard_mode_me_unauth():
    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/easy/me", timeout=15)
    assert r.status_code == 401


def test_leaderboard_mode_me_invalid():
    email = f"test_lbme2_{uuid.uuid4().hex[:6]}@example.com"
    tok, _ = _register(email, "LBme2")
    r = requests.get(f"{BASE_URL}/api/leaderboard/mode/medium/me",
                     headers={"Authorization": f"Bearer {tok}"}, timeout=15)
    assert r.status_code == 400


# ===== Forgot / Reset password =====
async def _get_token_from_db(user_email):
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    user = await db.users.find_one({"email": user_email.lower()})
    if not user:
        return None
    rec = await db.password_reset_tokens.find_one({"user_id": user["user_id"], "used": False}, sort=[("expires_at", -1)])
    client.close()
    return rec["token"] if rec else None


def _get_reset_token(email):
    return asyncio.get_event_loop().run_until_complete(_get_token_from_db(email))


def test_forgot_password_creates_token_for_known_user():
    email = f"test_fp_{uuid.uuid4().hex[:6]}@example.com"
    _register(email, "FPUser")
    r = requests.post(f"{BASE_URL}/api/auth/forgot-password", json={"email": email}, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    token = _get_reset_token(email)
    assert token, "Reset token should be created in db.password_reset_tokens"


def test_forgot_password_unknown_email_returns_200_no_enumeration():
    unknown = f"nonexistent_{uuid.uuid4().hex[:8]}@example.com"
    r = requests.post(f"{BASE_URL}/api/auth/forgot-password", json={"email": unknown}, timeout=15)
    assert r.status_code == 200
    assert r.json().get("ok") is True


def test_reset_password_updates_hash_and_invalidates_token():
    email = f"test_rp_{uuid.uuid4().hex[:6]}@example.com"
    _register(email, "RPUser")
    r = requests.post(f"{BASE_URL}/api/auth/forgot-password", json={"email": email}, timeout=15)
    assert r.status_code == 200
    token = _get_reset_token(email)
    assert token

    new_pass = "NewPassword456!"
    r = requests.post(f"{BASE_URL}/api/auth/reset-password",
                      json={"token": token, "new_password": new_pass}, timeout=15)
    assert r.status_code == 200

    # Old password fails
    r_old = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": PASS}, timeout=15)
    assert r_old.status_code == 401

    # New password works
    r_new = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": new_pass}, timeout=15)
    assert r_new.status_code == 200

    # Token reuse blocked
    r_reuse = requests.post(f"{BASE_URL}/api/auth/reset-password",
                            json={"token": token, "new_password": "Another1!"}, timeout=15)
    assert r_reuse.status_code == 400


def test_reset_password_invalid_token_400():
    r = requests.post(f"{BASE_URL}/api/auth/reset-password",
                      json={"token": "definitely_not_a_real_token_xxx", "new_password": "Whatever9!"}, timeout=15)
    assert r.status_code == 400
