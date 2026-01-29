from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib
from typing import List, Optional, Union

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

def check_repo_access(repo: Repository, user: User, required_permission: str, db: Session):
    """
    `required_permission` can be: "read", "write", "admin"
    
    Raises exceptions if permissions won't suffice.
    """
    
    if repo.owner_id == user.id:
        return True
    
    if not repo.is_private and required_permission == "read":
        return True
    
    collaborator = db.query(Collaborator).filter(
        Collaborator.repo_id == repo.id,
        Collaborator.user_id == user.id
    ).first()
    
    if not collaborator:
        raise HTTPException(
            status_code=status.HTTP_403_UNAUTHORIZED,
            detail="Access Denied"
        )
        
    permission_levels = {"read": 0, "write": 1, "admin": 2}
        
    if permission_levels[collaborator.permission_level] >= permission_levels[required_permission]:
        return True
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Insufficient permissions. Required: {required_permission}"
    )

def generate_commit_hash(message: str, author_id: int, timestamp: datetime) -> str:
    data = f"{message}|{author_id}|{timestamp.isoformat()}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def get_repo(repo_id: int, db: Session) -> Repository:
    """Gets a repo using an id
    
    Raises exception if repository not found
    """
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    return repo

def get_branch(repo_id: int, db: Session, branch_id: Optional[int] = None, name: Optional[str] = None) -> Union[Branch, List[Branch]]:
    """Gets a branch using an id
    
    Returns `Branch` when `branch_id` or `name` is provided,
    else returns all branches matching `repo_id`
    
    Raises exception if branch not found
    """
    if branch_id:
        branch = db.query(Branch).filter(
            Branch.repo_id == repo_id,
            Branch.id == branch_id           
            ).first()
    elif name:
        branch = db.query(Branch).filter(
            Branch.repo_id == repo_id,
            Branch.name == name           
            ).first()
    else:
        return db.query(Branch).filter(
            Branch.repo_id == repo_id
        ).all()
    
    if not branch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Branch not found"
        )  
    return branch

@router.post("/", response_model=RepositoryResponse)
@limiter.limit("50/hour")
def create_repository(request: Request, repo_data: RepositoryCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Creates a repo for given user with given data"""
    
    if not db.query(User).filter(User.id == user.id).first():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User:{user.username} not found"
        )
    
    if db.query(Repository).filter(
        Repository.owner_id == user.id,
        Repository.name == repo_data.name
        ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You already have a repository with the name \"{repo_data.name}\""
        )
    
    new_repo = Repository(
        name=repo_data.name,
        description=repo_data.description,
        is_private=repo_data.is_private,
        default_branch=repo_data.default_branch
    )
    
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    
    return new_repo

@router.get("/", response_model=List[RepositoryResponse])
def list_repositories(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    owned_repos = db.query(Repository).filter(Repository.owner_id == user.id).all()
    
    collaborated_repos = db.query(Repository).join(
        Collaborator, 
        Collaborator.repo_id == Repository.id
    ).filter(
        Collaborator.user_id == user.id
    ).all()
    
    all_repos = {repo.id: repo for repo in owned_repos}
    for repo in collaborated_repos:
        if repo.id not in all_repos:
            all_repos[repo.id] = repo
            
    return list(all_repos.values())

@router.get("/{repo_id}", response_model=RepositoryResponse)
def get_repository(repo_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    return repo
    
@router.put("/{repo_id}", response_model=RepositoryResponse)
def update_repository(repo_id: int, repo_data: RepositoryUpdate,
                      user: User = Depends(get_current_user),
                      csrf: bool = Depends(verify_csrf),
                      db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "admin", db)
    
    if repo_data.name is not None:
        existing = db.query(Repository).filter(
            Repository.owner_id == user.id,
            Repository.name == repo_data.name,
            Repository.id != repo_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Repository name already exists"
            )
        repo.name = repo_data.name
        
    if repo_data.description is not None:
        repo.description = repo_data.description
        
    if repo_data.is_private is not None:
        repo.is_private = repo_data.is_private
        
    if repo_data.default_branch is not None:
        get_branch(repo_id, db, name=repo_data.default_branch)
        repo.default_branch = repo_data.default_branch
    
    repo.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(repo)
    
    return repo
    
@router.delete("/{repo_id}")
@limiter.limiter("100/hour")
def delete_repository(repo_id: int,
                      user: User = Depends(get_current_user),
                      csrf: bool = Depends(verify_csrf),
                      db: Session = Depends(get_db)
                    ):
    repo = get_repo(repo_id, db)
    
    if repo.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only repository owner can delete repository"
        )
    
    db.delete(repo)
    db.commit()
    
    return {"status": "ok"}

@router.post("/{repo_id}/branches", response_model=BranchResponse)
@limiter.limit("30/hour")
def create_branch(repo_id: int,
                  branch_data: BranchCreate,
                  user: User = Depends(get_current_user),
                  csrf: bool = Depends(verify_csrf),
                  db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    
    existing = (
        db.query(Branch)
        .filter(Branch.repo_id == repo_id, Branch.name == branch_data.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Branch with this name already exists"
        )
        
    new_branch = Branch(
        name=branch_data.name,
        repo_id=repo_id
    )

    if branch_data.source_branch_id:
        source_branch = (
            db.query(Branch)
            .filter(
                Branch.id == branch_data.source_branch_id,
                Branch.repo_id == repo_id
            )
            .first()
        )
        
        if not source_branch:
            raise HTTPException(
                status_code=400,
                detail="Source branch not found in repository"
            )
            
        new_branch.last_commit_id = source_branch.last_commit_id
        
    db.add(new_branch)
    db.commit()
    db.refresh(new_branch)
    
    return new_branch
    
@router.get("/{repo_id}/branches", response_model=List[BranchResponse])
def list_branches(repo_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    return get_branch(repo_id, db)

@router.delete("/{repo_id}/branches/{branch_id}")
@limiter.limiter("20/hour")
def delete_branch(repo_id: int, branch_id: int,
                  user: User = Depends(get_current_user),
                  csrf: bool = Depends(verify_csrf),
                  db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    branch = get_branch(repo_id, db, branch_id=branch_id)
    if branch.name == repo.default_branch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default branch"
        )
    db.delete(branch)
    db.commit()
    
    return {"status": "ok"}