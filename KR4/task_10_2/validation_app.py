from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, conint, constr

app = FastAPI(title="Task 10.2 - Validation")


class ValidationErrorDetail(BaseModel):
    field: str
    message: str


class ValidationErrorResponse(BaseModel):
    error_code: str
    message: str
    details: list[ValidationErrorDetail]


class User(BaseModel):
    username: str
    age: conint(gt=18)
    email: EmailStr
    password: constr(min_length=8, max_length=16)
    phone: Optional[str] = "Unknown"


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    details = [
        ValidationErrorDetail(
            field=".".join(str(part) for part in error.get("loc", []) if part != "body"),
            message=error.get("msg", "Invalid value"),
        )
        for error in exc.errors()
    ]
    body = ValidationErrorResponse(
        error_code="VALIDATION_ERROR",
        message="Request validation failed",
        details=details,
    )
    return JSONResponse(status_code=422, content=body.model_dump())


@app.post("/users/register", status_code=201)
def register_user(user: User) -> dict[str, str]:
    return {"message": f"User {user.username} registered successfully"}
