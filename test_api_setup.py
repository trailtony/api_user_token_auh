from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Data(BaseModel):
    name: str


@app.post("/create/")
async def create(data: Data):
    return {"data": data}


@app.get("/test_endpoint/{item_id}/")
async def test_endpoint(item_id: str, query: int = 1):
    return {"message": "Test endpoint is working!"}
