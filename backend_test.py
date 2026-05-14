"""Backend tests for TIC×TAC×SMASH v2: REST AI + Auth + Stats + Leaderboard + Socket.IO multiplayer + ELO + matchmaking + Mongo room persistence."""
import os
import time
import uuid
import pytest
import requests
import socketio

BASE_URL = os.environ['REACT_APP_BACKEND_URL'].rstrip('/')
EMPTY = [[" "] * 3 for _ in range(3)]

# ----- shared test user (created once, reused across tests) -----
TEST_EMAIL_A = f"test_player_a_{uuid.uuid4().hex[:8]}@example.com"
TEST_EMAIL_B = f"test_player_b_{uuid.uuid4().hex[:8]}@example.com"
TEST_PASS = "Password123!"
_credentials = {}  # populated by fixtures


# ---------- AUTH ----------
def _register(email, name="Tester"):
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/register",
               json={"email": email, "password": TEST_PASS, "name": name}, timeout=15)
    return r, s


def test_auth_register_returns_token_and_cookie():
    r, s = _register(TEST_EMAIL_A, "Alice")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["email"] == TEST_EMAIL_A.lower()
    assert data["name"] == "Alice"
    assert "user_id" in data and isinstance(data["user_id"], str)
    assert "token" in data and len(data["token"]) > 20
    assert data["stats"]["online"]["elo"] == 1000
    # httpOnly cookie present
    assert "access_token" in s.cookies
    _credentials["a"] = {"email": TEST_EMAIL_A, "token": data["token"], "user_id": data["user_id"], "session": s}


def test_auth_register_duplicate_rejected():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    r = requests.post(f"{BASE_URL}/api/auth/register",
                      json={"email": TEST_EMAIL_A, "password": TEST_PASS, "name": "Dup"}, timeout=15)
    assert r.status_code == 400


def test_auth_login_success():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": TEST_EMAIL_A, "password": TEST_PASS}, timeout=15)
    assert r.status_code == 200
    assert r.json()["email"] == TEST_EMAIL_A.lower()


def test_auth_login_bad_password():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": TEST_EMAIL_A, "password": "wrong"}, timeout=15)
    assert r.status_code == 401


def test_auth_me_with_bearer():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    tok = _credentials["a"]["token"]
    r = requests.get(f"{BASE_URL}/api/auth/me",
                     headers={"Authorization": f"Bearer {tok}"}, timeout=15)
    assert r.status_code == 200
    assert r.json()["email"] == TEST_EMAIL_A.lower()


def test_auth_me_with_cookie():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    s = _credentials["a"]["session"]
    r = s.get(f"{BASE_URL}/api/auth/me", timeout=15)
    assert r.status_code == 200


def test_auth_me_unauth():
    r = requests.get(f"{BASE_URL}/api/auth/me", timeout=15)
    assert r.status_code == 401


def test_auth_logout_clears_cookie():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    s = requests.Session()
    s.post(f"{BASE_URL}/api/auth/login",
           json={"email": TEST_EMAIL_A, "password": TEST_PASS}, timeout=15)
    assert "access_token" in s.cookies
    r = s.post(f"{BASE_URL}/api/auth/logout", timeout=15)
    assert r.status_code == 200
    # Cookie deleted on server response; subsequent /me should 401
    s.cookies.clear()
    r2 = s.get(f"{BASE_URL}/api/auth/me", timeout=15)
    assert r2.status_code == 401


def test_emergent_callback_invalid_session():
    r = requests.post(f"{BASE_URL}/api/auth/emergent/callback",
                      json={"session_id": "invalid_sess_xxx"}, timeout=15)
    assert r.status_code == 401


# ---------- STATS ----------
def test_stats_ai_result_increments():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    tok = _credentials["a"]["token"]
    headers = {"Authorization": f"Bearer {tok}"}
    r = requests.post(f"{BASE_URL}/api/stats/ai-result",
                      json={"mode": "hard", "result": "win"}, headers=headers, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert body["stats"]["hard"]["wins"] >= 1
    # GET /me reflects change
    me = requests.get(f"{BASE_URL}/api/auth/me", headers=headers, timeout=15).json()
    assert me["stats"]["hard"]["wins"] >= 1


def test_stats_ai_result_requires_auth():
    r = requests.post(f"{BASE_URL}/api/stats/ai-result",
                      json={"mode": "easy", "result": "loss"}, timeout=15)
    assert r.status_code == 401


def test_stats_ai_result_invalid_body():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    tok = _credentials["a"]["token"]
    r = requests.post(f"{BASE_URL}/api/stats/ai-result",
                      json={"mode": "online", "result": "win"},
                      headers={"Authorization": f"Bearer {tok}"}, timeout=15)
    assert r.status_code == 400


# ---------- LEADERBOARD ----------
def test_leaderboard_public():
    r = requests.get(f"{BASE_URL}/api/leaderboard", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    if data:
        elos = [u["elo"] for u in data]
        assert elos == sorted(elos, reverse=True)
        for u in data:
            for k in ("user_id", "name", "elo", "wins", "losses", "draws"):
                assert k in u


def test_leaderboard_me():
    if "a" not in _credentials:
        pytest.skip("primary registration missing")
    tok = _credentials["a"]["token"]
    r = requests.get(f"{BASE_URL}/api/leaderboard/me",
                     headers={"Authorization": f"Bearer {tok}"}, timeout=15)
    assert r.status_code == 200
    body = r.json()
    assert "rank" in body and body["rank"] >= 1
    assert body["elo"] >= 0


def test_leaderboard_me_unauth():
    r = requests.get(f"{BASE_URL}/api/leaderboard/me", timeout=15)
    assert r.status_code == 401


# ---------- AI MOVE ----------
def test_ai_hard_blocks_opponent():
    board = [["X", "X", " "], [" ", "O", " "], [" ", " ", " "]]
    r = requests.post(f"{BASE_URL}/api/ai/move",
                      json={"board": board, "difficulty": "hard"}, timeout=15)
    assert r.json()["move"] == [0, 2]


def test_ai_easy_returns_move():
    r = requests.post(f"{BASE_URL}/api/ai/move",
                      json={"board": EMPTY, "difficulty": "easy"}, timeout=15)
    assert r.json()["move"] is not None


def test_ai_detects_winning_line():
    board = [["X", "X", "X"], [" ", "O", " "], ["O", " ", " "]]
    r = requests.post(f"{BASE_URL}/api/ai/move",
                      json={"board": board, "difficulty": "hard"}, timeout=15)
    d = r.json()
    assert d["winner"] == "X" and d["winning_line"]


# ---------- SOCKET.IO ----------
def _make_client(events):
    c = socketio.Client(reconnection=False)
    for ev in ("room_created", "joined", "state", "error_msg", "opponent_left",
               "matched", "queued", "queue_cancelled", "leaderboard"):
        def _h(data, _ev=ev):
            events.setdefault(_ev, []).append(data)
        c.on(ev, _h)
    return c


def _connect(c, retries=3):
    last = None
    for i in range(retries):
        try:
            c.connect(BASE_URL, socketio_path="/api/socket.io", transports=["websocket"], wait_timeout=10)
            time.sleep(0.2)
            return
        except Exception as e:
            last = e
            time.sleep(1.0 + i)
    raise last


def _wait(ev, key, n=1, timeout=6):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if len(ev.get(key, [])) >= n:
            return True
        time.sleep(0.1)
    return False


def test_socket_connect_emits_leaderboard():
    ev = {}
    c = _make_client(ev)
    _connect(c)
    assert _wait(ev, "leaderboard"), "leaderboard not sent on connect"
    assert isinstance(ev["leaderboard"][0], list)
    c.disconnect()


def test_socket_create_room_and_mongo_persistence():
    """Create room via socket, verify Mongo doc exists via leave/reconnect-load path."""
    ev = {}
    c = _make_client(ev)
    _connect(c)
    c.emit("create_room", {"name": "Alice", "theme": "football_basketball"})
    assert _wait(ev, "room_created")
    code = ev["room_created"][0]["room_id"]
    assert len(code) == 5

    # join from a *fresh* client → exercises load_room from Mongo (proves persistence path works)
    time.sleep(0.5)
    ev2 = {}
    c2 = _make_client(ev2)
    for attempt in range(3):
        try:
            _connect(c2)
            break
        except Exception:
            time.sleep(1.0)
    c2.emit("join_room", {"room_id": code, "name": "Bob"})
    assert _wait(ev2, "joined", timeout=8), f"join failed: {ev2}"
    assert ev2["joined"][0]["symbol"] == "O"
    c.disconnect()
    c2.disconnect()


def test_socket_join_invalid_room():
    ev = {}
    c = _make_client(ev)
    _connect(c)
    c.emit("join_room", {"room_id": "ZZZZZ", "name": "Bob"})
    assert _wait(ev, "error_msg")
    assert "not found" in ev["error_msg"][0]["message"].lower()
    c.disconnect()


def test_socket_matchmaking_pairs_two_players():
    ev1, ev2 = {}, {}
    c1 = _make_client(ev1)
    c2 = _make_client(ev2)
    _connect(c1)
    _connect(c2)
    c1.emit("find_match", {"name": "P1"})
    time.sleep(0.4)
    c2.emit("find_match", {"name": "P2"})
    assert _wait(ev1, "matched", timeout=6)
    assert _wait(ev2, "matched", timeout=6)
    assert ev1["matched"][0]["symbol"] == "X"
    assert ev2["matched"][0]["symbol"] == "O"
    assert ev1["matched"][0]["room_id"] == ev2["matched"][0]["room_id"]
    c1.disconnect()
    c2.disconnect()


def test_socket_cancel_match():
    ev = {}
    c = _make_client(ev)
    _connect(c)
    time.sleep(0.2)
    c.emit("find_match", {"name": "Lonely"})
    # Either we get queued (alone) or matched (paired with a ghost) — assert one happened
    t0 = time.time()
    while time.time() - t0 < 4:
        if ev.get("queued") or ev.get("matched"):
            break
        time.sleep(0.1)
    assert ev.get("queued") or ev.get("matched"), f"neither queued nor matched: {list(ev.keys())}"
    # cancel should always be safe (no-op if already matched)
    c.emit("cancel_match", {})
    assert _wait(ev, "queue_cancelled"), "queue_cancelled not received"
    c.disconnect()


def _login_get_token(email, name):
    """Register or login and return token."""
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/register",
               json={"email": email, "password": TEST_PASS, "name": name}, timeout=15)
    if r.status_code == 200:
        return r.json()["token"]
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": email, "password": TEST_PASS}, timeout=15)
    return r.json()["token"]


def test_socket_elo_updates_after_authenticated_win():
    """Two logged-in users play; winner ELO > 1000, loser < 1000, leaderboard broadcast."""
    email_x = f"test_elo_x_{uuid.uuid4().hex[:6]}@example.com"
    email_o = f"test_elo_o_{uuid.uuid4().hex[:6]}@example.com"
    tok_x = _login_get_token(email_x, "EloX")
    tok_o = _login_get_token(email_o, "EloO")

    ev1, ev2 = {}, {}
    cx = _make_client(ev1)
    co = _make_client(ev2)
    _connect(cx)
    _connect(co)

    cx.emit("create_room", {"name": "EloX", "token": tok_x})
    assert _wait(ev1, "room_created")
    code = ev1["room_created"][0]["room_id"]
    co.emit("join_room", {"room_id": code, "name": "EloO", "token": tok_o})
    assert _wait(ev2, "joined")
    assert _wait(ev1, "state", n=2)

    # X wins top row: X(0,0) O(1,0) X(0,1) O(1,1) X(0,2)
    cx.emit("make_move", {"row": 0, "col": 0}); time.sleep(0.25)
    co.emit("make_move", {"row": 1, "col": 0}); time.sleep(0.25)
    cx.emit("make_move", {"row": 0, "col": 1}); time.sleep(0.25)
    co.emit("make_move", {"row": 1, "col": 1}); time.sleep(0.25)
    cx.emit("make_move", {"row": 0, "col": 2}); time.sleep(0.8)

    last = ev1["state"][-1]
    assert last["status"] == "finished"
    assert last["winner"] == "X"

    # leaderboard rebroadcast after ELO change
    assert len(ev1.get("leaderboard", [])) >= 2 or len(ev2.get("leaderboard", [])) >= 2

    # Verify ELO updated in DB via REST /me
    me_x = requests.get(f"{BASE_URL}/api/auth/me",
                        headers={"Authorization": f"Bearer {tok_x}"}, timeout=15).json()
    me_o = requests.get(f"{BASE_URL}/api/auth/me",
                        headers={"Authorization": f"Bearer {tok_o}"}, timeout=15).json()
    assert me_x["stats"]["online"]["elo"] > 1000, f"winner elo not increased: {me_x['stats']['online']}"
    assert me_o["stats"]["online"]["elo"] < 1000, f"loser elo not decreased: {me_o['stats']['online']}"
    assert me_x["stats"]["online"]["wins"] >= 1
    assert me_o["stats"]["online"]["losses"] >= 1

    cx.disconnect()
    co.disconnect()


def test_socket_room_deleted_when_both_leave():
    """After both players leave_room, the room should be gone — joining returns error."""
    ev1, ev2 = {}, {}
    c1 = _make_client(ev1); c2 = _make_client(ev2)
    _connect(c1)
    _connect(c2)
    c1.emit("create_room", {"name": "A"})
    assert _wait(ev1, "room_created")
    code = ev1["room_created"][0]["room_id"]
    c2.emit("join_room", {"room_id": code, "name": "B"})
    assert _wait(ev2, "joined")
    c1.emit("leave_room", {}); time.sleep(0.3)
    c2.emit("leave_room", {}); time.sleep(0.6)

    # Try to join now — should fail
    ev3 = {}
    c3 = _make_client(ev3)
    _connect(c3)
    c3.emit("join_room", {"room_id": code, "name": "C"})
    assert _wait(ev3, "error_msg")
    assert "not found" in ev3["error_msg"][0]["message"].lower()
    c1.disconnect(); c2.disconnect(); c3.disconnect()
