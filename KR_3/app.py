import os
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from database import get_db_connection, init_db

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MODE = os.getenv("MODE", "DEV").upper()
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

if MODE not in {"DEV", "PROD"}:
    raise ValueError("MODE must be DEV or PROD")

if MODE == "DEV":
    app = FastAPI(
        title="KR3 FastAPI",
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )
else:
    app = FastAPI(
        title="KR3 FastAPI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
basic_security = HTTPBasic()
bearer_scheme = HTTPBearer(auto_error=False)

# In-memory role mapping for RBAC.
user_roles: dict[str, str] = {"admin": "admin", "guest": "guest"}
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"create", "read", "update", "delete"},
    "user": {"read", "update"},
    "guest": {"read"},
}

# Simple in-memory fixed-window rate limiting.
rate_limit_state: dict[str, list[float]] = defaultdict(list)
WINDOW_SECONDS = 60


class UserBase(BaseModel):
    username: str = Field(min_length=1)


class User(UserBase):
    password: str = Field(min_length=1)


class UserInDB(UserBase):
    hashed_password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TodoCreate(BaseModel):
    title: str
    description: str


class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool


class TodoOut(BaseModel):
    id: int
    title: str
    description: str
    completed: bool


def apply_rate_limit(request: Request, bucket: str, max_requests: int) -> None:
    now = time.time()
    client = request.client.host if request.client else "unknown"
    key = f"{bucket}:{client}"
    rate_limit_state[key] = [ts for ts in rate_limit_state[key] if now - ts < WINDOW_SECONDS]
    if len(rate_limit_state[key]) >= max_requests:
        raise HTTPException(status_code=429, detail="Too many requests")
    rate_limit_state[key].append(now)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {"sub": subject, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_all_users() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT username, password FROM users").fetchall()
    return [{"username": row["username"], "password": row["password"]} for row in rows]


def get_user_by_username_secure(username: str) -> dict[str, Any] | None:
    for row in get_all_users():
        if secrets.compare_digest(row["username"], username):
            return row
    return None


def auth_user(credentials: HTTPBasicCredentials = Depends(basic_security)) -> dict[str, Any]:
    user = get_user_by_username_secure(credentials.username)
    if user is None or not verify_password(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or missing token") from None
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return str(username)


def require_role(allowed_roles: set[str]):
    def _checker(current_user: str = Depends(get_current_user)) -> str:
        role = user_roles.get(current_user, "guest")
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Access denied")
        return current_user

    return _checker


@app.on_event("startup")
def startup_event() -> None:
    init_db()
    # Seed default admin/guest users for RBAC demos.
    defaults = {"admin": "admin123", "guest": "guest123"}
    with get_db_connection() as conn:
        for username, raw_password in defaults.items():
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hash_password(raw_password)),
                )
        conn.commit()


@app.get("/basic/login")
def basic_login(user: dict[str, Any] = Depends(auth_user)) -> dict[str, str]:
    return {"message": f"Welcome, {user['username']}!"}


@app.get("/login")
def login_get(user: dict[str, Any] = Depends(auth_user)) -> dict[str, str]:
    return {"message": "You got my secret, welcome"}


@app.post("/register", status_code=201)
def register(payload: User, request: Request) -> dict[str, str]:
    apply_rate_limit(request, "register", 1)
    existing = get_user_by_username_secure(payload.username)
    if existing is not None:
        raise HTTPException(status_code=409, detail="User already exists")

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (payload.username, hash_password(payload.password)),
        )
        conn.commit()

    if payload.username not in user_roles:
        user_roles[payload.username] = "user"
    return {"message": "New user created"}


@app.post("/login")
def login_post(payload: LoginRequest, request: Request) -> dict[str, str]:
    apply_rate_limit(request, "login", 5)
    user = get_user_by_username_secure(payload.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Authorization failed")
    token = create_access_token(payload.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected_resource")
def protected_resource(current_user: str = Depends(require_role({"admin", "user"}))) -> dict[str, str]:
    return {"message": f"Access granted for {current_user}"}


@app.post("/admin/resource")
def admin_create_resource(current_user: str = Depends(require_role({"admin"}))) -> dict[str, str]:
    return {"message": f"Admin action completed by {current_user}"}


@app.get("/user/resource")
def user_read_resource(current_user: str = Depends(require_role({"admin", "user", "guest"}))) -> dict[str, str]:
    role = user_roles.get(current_user, "guest")
    permissions = sorted(ROLE_PERMISSIONS.get(role, {"read"}))
    return {"message": f"Resource visible for {current_user}", "permissions": ", ".join(permissions)}


@app.post("/todos", response_model=TodoOut, status_code=201)
def create_todo(todo: TodoCreate) -> TodoOut:
    with get_db_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
            (todo.title, todo.description, 0),
        )
        conn.commit()
        todo_id = cursor.lastrowid

        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,)).fetchone()

    return TodoOut(id=row["id"], title=row["title"], description=row["description"], completed=bool(row["completed"]))


@app.get("/todos/{todo_id}", response_model=TodoOut)
def get_todo(todo_id: int) -> TodoOut:
    with get_db_connection() as conn:
        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return TodoOut(id=row["id"], title=row["title"], description=row["description"], completed=bool(row["completed"]))


@app.put("/todos/{todo_id}", response_model=TodoOut)
def update_todo(todo_id: int, todo: TodoUpdate) -> TodoOut:
    with get_db_connection() as conn:
        existing = conn.execute("SELECT id FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="Todo not found")

        conn.execute(
            "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
            (todo.title, todo.description, int(todo.completed), todo_id),
        )
        conn.commit()
        row = conn.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,)).fetchone()
    return TodoOut(id=row["id"], title=row["title"], description=row["description"], completed=bool(row["completed"]))


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int) -> dict[str, str]:
    with get_db_connection() as conn:
        existing = conn.execute("SELECT id FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="Todo not found")
        conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
    return {"message": "Todo deleted successfully"}
