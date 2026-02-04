from fastapi import FastAPI, Depends, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.database import engine, Base
from app.auth import router as auth_router, limiter, verify_csrf, get_current_user
from app.repos import router as repos_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Github")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router)
app.include_router(repos_router)

@app.get("/protected")
def protected_route(user = Depends(get_current_user)):
    return {
        "message": "Welcome home",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }
    
@app.post("/protected/action")
def protected_action(
    request: Request,
    csrf_valid: bool = Depends(verify_csrf),
    user = Depends(get_current_user)
):
    return {
        "message": "Action completed successfully",
        "user": user.username
    }

@app.get("/")
def root():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)