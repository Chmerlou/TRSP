from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def root():
    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
    <meta charset="UTF-8">
    <title>Пример простой страницы html</title>
    </head>
    <body>
    Я ОБОЖАЮ ВСТАВАТЬ К ПЕРВОЙ ПАРЕ :)
    </body>
    </html>
    """
    return html_content