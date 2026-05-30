from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Task 10.1 - Custom Exceptions")


class ErrorResponse(BaseModel):
    error_code: str
    message: str


class CustomExceptionA(Exception):
    def __init__(self, message: str = "Business rule violated") -> None:
        self.message = message
        super().__init__(message)


class CustomExceptionB(Exception):
    def __init__(self, message: str = "Resource not found") -> None:
        self.message = message
        super().__init__(message)


@app.exception_handler(CustomExceptionA)
async def handle_custom_exception_a(_request: Request, exc: CustomExceptionA) -> JSONResponse:
    print(f"[CustomExceptionA] {exc.message}")
    body = ErrorResponse(error_code="CUSTOM_A", message=exc.message)
    return JSONResponse(status_code=400, content=body.model_dump())


@app.exception_handler(CustomExceptionB)
async def handle_custom_exception_b(_request: Request, exc: CustomExceptionB) -> JSONResponse:
    print(f"[CustomExceptionB] {exc.message}")
    body = ErrorResponse(error_code="CUSTOM_B", message=exc.message)
    return JSONResponse(status_code=404, content=body.model_dump())


ITEMS: dict[int, str] = {1: "alpha", 2: "beta"}


@app.get("/items/{item_id}/validate")
def validate_item(item_id: int, min_id: int = 1) -> dict[str, str]:
    if item_id < min_id:
        raise CustomExceptionA(f"Item id {item_id} is below minimum {min_id}")
    return {"message": f"Item {item_id} is valid"}


@app.get("/items/{item_id}")
def get_item(item_id: int) -> dict[str, str | int]:
    if item_id not in ITEMS:
        raise CustomExceptionB(f"Item with id {item_id} not found")
    return {"id": item_id, "name": ITEMS[item_id]}
