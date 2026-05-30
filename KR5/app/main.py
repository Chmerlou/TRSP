import os

from fastapi import FastAPI

from app.routers import admin, rooms, tasks, users
from app.schemas import HealthResponse

app = FastAPI(title="Tasks API", version="1.0.0")

app.include_router(tasks.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(rooms.router)


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "env": os.getenv("APP_ENV", "local")}
