from fastapi import FastAPI, Depends, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

if __name__ == "__main__":
    import sys
    from pathlib import Path
    import uvicorn

    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import engine, Base
from app.auth import router as auth_router, limiter
from app.repos import router as repos_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Github")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router)
app.include_router(repos_router)

@app.get("/")
def root():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)