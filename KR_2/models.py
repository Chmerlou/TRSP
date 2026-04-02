import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class UserCreate(BaseModel):
    name: str
    email: str
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        if not pattern.match(value):
            raise ValueError("Некорректный формат email")
        return value


class Product(BaseModel):
    product_id: int
    name: str
    category: str
    price: float


class LoginRequest(BaseModel):
    username: str
    password: str


class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, value: str) -> str:
        pattern = re.compile(
            r"^[a-zA-Z]{2,3}(?:-[a-zA-Z]{2})?(?:,[a-zA-Z]{2,3}(?:-[a-zA-Z]{2})?(?:;q=(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?))?)*$"
        )
        if not pattern.match(value):
            raise ValueError("Неверный формат заголовка Accept-Language")
        return value
