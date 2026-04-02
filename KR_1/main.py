from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse

from models import CalculateRequest, Feedback, User, UserWithAge

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = BASE_DIR / "index.html"

fixed_user = User(name="Daniil", id=1)
feedbacks: list[Feedback] = []


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(INDEX_HTML_PATH)


@app.post("/calculate")
async def calculate(data: CalculateRequest) -> dict[str, float]:
    return {"result": data.num1 + data.num2}


@app.get("/users")
async def get_user() -> User:
    return fixed_user


@app.post("/user")
async def check_user_age(user: UserWithAge) -> dict[str, Any]:
    return {**user.model_dump(), "is_adult": user.age >= 18}


@app.post("/feedback")
async def create_feedback(feedback: Feedback) -> dict[str, str]:
    feedbacks.append(feedback)
    return {"message": f"Спасибо, {feedback.name}! Ваш отзыв сохранён."}