from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib

from database import get_db
from models import Repository, Branch, File, Issue, IssueComment, PullRequest, Collaborator, User
from schemas import (RepositoryCreate, RepositoryUpdate, RepositoryResponse,
                     BranchCreate, BranchResponse, CommitCreate, CommitResponse,
                     CollaboratorAdd, CollaboratorResponse, FileChange, FileResponse,
                     IssueCommentCreate, IssueCommentResponse, IssueCreate, IssueResponse,
                     IssueUpdate, PullRequestCreate, PullRequestResponse, PullRequestUpdate,
                    )
from auth import get_current_user, verify_csrf, limiter

router = APIRouter(prefix="/repos", tags=["repositories"])

@router.post("/", response_model=RepositoryResponse)
@limiter.limit("50/hour")
def create_repository(request, repo_data: RepositoryCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    

def get_repo(repo_id: int, db: Session) -> Repository:
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    return repo

