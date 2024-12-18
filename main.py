from fastapi import FastAPI

from app.api.routers import auth_router, common_router

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


app.include_router(auth_router.router, prefix="/users", tags=["Users"])
app.include_router(common_router.router, prefix="/admin", tags=["Admin"])
