from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

@app.get("/test_endpoint/{item_id}/")
async def test_endpoint(item_id: str, query: int = 1):
    return {"message": "Test endpoint is working!"}
