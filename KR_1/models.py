from pydantic import BaseModel, Field, field_validator
import re


class User(BaseModel):
    name: str
    id: int


class UserWithAge(BaseModel):
    name: str
    age: int


class CalculateRequest(BaseModel):
    num1: float
    num2: float


class Feedback(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    message: str = Field(min_length=10, max_length=500)

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        pattern = re.compile(r"\b(кринж\w*|рофл\w*|вайб\w*)\b", re.IGNORECASE)
        if pattern.search(value):
            raise ValueError("Использование недопустимых слов")
        return value
