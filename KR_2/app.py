from datetime import datetime
import time
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from itsdangerous import BadSignature, Signer
from pydantic import ValidationError

from models import CommonHeaders, LoginRequest, Product, UserCreate

app = FastAPI()

SECRET_KEY = "kr2-very-secret-key"
SESSION_COOKIE = "session_token"
SESSION_MAX_AGE_SECONDS = 300
SESSION_REFRESH_AFTER_SECONDS = 180

signer = Signer(SECRET_KEY)
active_sessions: dict[str, dict[str, Any]] = {}


sample_products: list[Product] = [
    Product(product_id=123, name="Smartphone", category="Electronics", price=599.99),
    Product(product_id=456, name="Phone Case", category="Accessories", price=19.99),
    Product(product_id=789, name="Iphone", category="Electronics", price=1299.99),
    Product(product_id=101, name="Headphones", category="Accessories", price=99.99),
    Product(product_id=202, name="Smartwatch", category="Electronics", price=299.99),
]


def create_session_token(user_id: str, timestamp: int) -> str:
    payload = f"{user_id}.{timestamp}"
    return signer.sign(payload.encode()).decode()


def decode_session_token(session_token: str) -> tuple[str, int]:
    try:
        payload = signer.unsign(session_token.encode()).decode()
    except BadSignature as error:
        raise HTTPException(status_code=401, detail="Invalid session") from error

    if "." not in payload:
        raise HTTPException(status_code=401, detail="Invalid session")

    user_id, timestamp_raw = payload.rsplit(".", 1)
    try:
        UUID(user_id)
        timestamp = int(timestamp_raw)
    except (ValueError, TypeError) as error:
        raise HTTPException(status_code=401, detail="Invalid session") from error

    return user_id, timestamp


def verify_session(session_token: str | None, response: Response | None = None) -> dict[str, Any]:
    if not session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id, last_activity = decode_session_token(session_token)
    now = int(time.time())

    if last_activity > now:
        raise HTTPException(status_code=401, detail="Invalid session")

    elapsed = now - last_activity
    if elapsed >= SESSION_MAX_AGE_SECONDS:
        raise HTTPException(status_code=401, detail="Session expired")

    profile = active_sessions.get(user_id)
    if profile is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if response is not None and SESSION_REFRESH_AFTER_SECONDS <= elapsed < SESSION_MAX_AGE_SECONDS:
        refreshed_token = create_session_token(user_id, now)
        response.set_cookie(
            key=SESSION_COOKIE,
            value=refreshed_token,
            httponly=True,
            secure=False,
            max_age=SESSION_MAX_AGE_SECONDS,
        )

    return {"user_id": user_id, "profile": profile}


def parse_accept_headers(
    user_agent: Annotated[str | None, Header(alias="User-Agent")] = None,
    accept_language: Annotated[str | None, Header(alias="Accept-Language")] = None,
) -> CommonHeaders:
    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Missing required headers")

    try:
        return CommonHeaders(user_agent=user_agent, accept_language=accept_language)
    except ValidationError as error:
        raise HTTPException(status_code=400, detail=error.errors()) from error


@app.post("/create_user")
async def create_user(user: UserCreate) -> dict[str, Any]:
    return user.model_dump()


@app.get("/product/{product_id}")
async def get_product(product_id: int) -> dict[str, Any]:
    for product in sample_products:
        if product.product_id == product_id:
            return product.model_dump()
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/search")
async def search_products(
    keyword: str,
    category: str | None = None,
    limit: int = Query(default=10, ge=1),
) -> list[dict[str, Any]]:
    filtered = [product for product in sample_products if keyword.lower() in product.name.lower()]

    if category is not None:
        filtered = [product for product in filtered if product.category.lower() == category.lower()]

    limited = filtered[:limit]
    return [product.model_dump() for product in limited]


@app.post("/login")
async def login(
    response: Response,
    request: Request,
) -> dict[str, str]:
    content_type = request.headers.get("content-type", "")
    data: dict[str, Any]

    if "application/json" in content_type:
        data = await request.json()
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form_data = await request.form()
        data = dict(form_data)
    else:
        raise HTTPException(status_code=400, detail="Unsupported request format")

    try:
        credentials = LoginRequest.model_validate(data)
    except ValidationError as error:
        raise HTTPException(status_code=400, detail=error.errors()) from error

    if credentials.username != "user123" or credentials.password != "password123":
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id = str(uuid4())
    now = int(time.time())
    active_sessions[user_id] = {"username": credentials.username}
    session_token = create_session_token(user_id, now)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    return {"message": "Login successful", "user_id": user_id}


@app.get("/user")
async def user_profile(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, Any]:
    try:
        session_data = verify_session(session_token, response)
        return session_data["profile"]
    except HTTPException:
        response.status_code = 401
        return {"message": "Unauthorized"}


@app.get("/profile")
async def profile(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, Any]:
    session_data = verify_session(session_token, response)
    return {
        "user_id": session_data["user_id"],
        "username": session_data["profile"]["username"],
    }


@app.get("/headers")
async def read_headers(
    headers: Annotated[CommonHeaders, Depends(parse_accept_headers)],
) -> dict[str, str]:
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app.get("/info")
async def info(
    response: Response,
    headers: Annotated[CommonHeaders, Depends(parse_accept_headers)],
) -> dict[str, Any]:
    response.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
