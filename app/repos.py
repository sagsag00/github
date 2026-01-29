from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import hashlib
from typing import List, Optional, Union

from database import get_db
from models import Repository, Branch, File, Issue, IssueComment, PullRequest, Collaborator, User, Commit
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
            status_code=status.HTTP_403_FORBIDDEN,
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

def get_user(user_id: int, db: Session) -> User:
    """Gets a user using an id
    
    Raises exception if user not found
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    return user

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

def _get_commit(repo_id: int, commit_id: int, db: Session) -> Commit:
    """Gets the commit with the provided id
    
    Raises exception if no commit has been found
    """
    commit = db.query(Commit).filter(
        Commit.repository_id == repo_id,
        Commit.id == commit_id
    ).first()
    if not commit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Couldn't find any commit with the povided id"
        )
        
    return commit

def get_latest_commit(repo_id: int, branch_id: int, db: Session) -> Union[Commit, None]:
    """Gets the latest commit of a branch.
    
    Raises exception if no commit has been found
    """
    commit = db.query(Commit).filter(
        Commit.repository_id == repo_id,
        Commit.branch_id == branch_id
        ).order_by(Commit.created_at.desc()).first()
    
    return commit

def copy_commits(source_branch: Branch, target_branch: Branch, db: Session):
    """Copies the commits from source to target"""
    repo_id = source_branch.repo_id
    latest_commit_target = get_latest_commit(repo_id, target_branch.id, db)

    source_commits = db.query(Commit).filter(
        Commit.repository_id == repo_id,
        Commit.branch_id == source_branch.id,
    ).order_by(Commit.created_at.asc(), Commit.id.asc()).all()
    
    for commit in source_commits:
        new_commit = Commit(
            repository_id = repo_id,
            branch_id=target_branch.id,
            message=commit.message,
            author_id=commit.author_id,
            parent_commit_id=latest_commit_target.id if latest_commit_target else None,
            created_at=datetime.utcnow(),
            commit_hash=generate_commit_hash(commit.message, commit.author_id, datetime.utcnow())
        )
        db.add(new_commit)
        latest_commit_target = new_commit

def _get_file(repo_id: int, file_id: int, db: Session) -> File:
    """Gets the file with the provided id
    
    Raises exception if the file doesn't exist
    """
    file = db.query(File).filter(
        File.repo_id == repo_id,
        File.id == file_id
    ).first()
    
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
        
    return file

def get_all_files(repo_id: int,
                  db: Session,
                  branch_id: Optional[int] = None,
                  commit_id: Optional[int] = None,
                  ) -> List[File]:
    """Gets all files using `repo_id`.
    if `branch_id` or `commit_id` is provided, 
    returns all files that are a part of them
    """
    if not branch_id and not commit_id:
        files = db.query(Repository).filter(
            Repository.id == repo_id
        ).first().files
        return files
    
    if commit_id:
        files = db.query(File).filter(
            File.repo_id == repo_id,
            File.commit_id == commit_id
        ).all()
        return files
    
    last_commit = get_latest_commit(repo_id, branch_id, db)
    files = db.query(File).filter(
        File.repo_id == repo_id,
        File.commit_id == last_commit.id
    )
    
    return files

def get_issue(repo_id: int, db: Session, issue_id: Optional[int]) -> Union[Issue, List[Issue]]:
    """Gets an issue using an id
    
    Returns `Issue` when `issue_id` is provided,
    else returns all issues matching `repo_id`
    
    Raises exception if issue not found
    """
    if not issue_id:
        return db.query(Issue).filter(
            Issue.repo_id == repo_id
        ).all()
        
    issue = db.query(Issue).filter(
        Issue.repo_id == repo_id,
        Issue.id == issue_id
    ).first()
    if not issue:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issue not found"
        )
        
    return issue

def get_pull_request(repo_id: int, pr_id: int, db: Session) -> PullRequest:
    """Gets the pull request with the provided id
    
    Raises exception if the pull request is not found
    """
    pr = db.query(PullRequest).filter(
        PullRequest.id == pr_id,
        PullRequest.repo_id == repo_id
    ).first()
    
    if not pr:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pull request not found"
        )
        
    return pr

def get_collaborator(repo_id: int, db: Session, user_id: Optional[int] = None) -> Union[Collaborator, List[Collaborator]]:
    """Gets a collaborator using an id
    
    Returns `Collaborator` when `user_id` is provided,
    else returns all issues matching `repo_id`
    
    Raises exception if collaborator not found
    """
    if not user_id:
        return db.query(Collaborator).filter(
            Collaborator.repo_id == repo_id
        ).all()
        
    collaborator = db.query(Collaborator).filter(
        Collaborator.repo_id == repo_id,
        Collaborator.user_id == user_id
    ).first()
    if not collaborator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Collaborator not found"
        )
        
    return collaborator
    
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
        ).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You already have a repository with the name \"{repo_data.name}\""
        )
    
    new_repo = Repository(
        name=repo_data.name,
        description=repo_data.description,
        is_private=repo_data.is_private,
        default_branch=repo_data.default_branch,
        owner_id=user.id
    )
    
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    
    default_branch = Branch(
        name=new_repo.default_branch,
        repo_id=new_repo.id
    )
    db.add(default_branch)
    db.commit()
    
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
        # Verify the branch exists
        get_branch(repo_id, db, name=repo_data.default_branch)
        repo.default_branch = repo_data.default_branch
    
    repo.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(repo)
    
    return repo
    
@router.delete("/{repo_id}")
@limiter.limit("100/hour")
def delete_repository(repo_id: int,
                      request: Request,
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
                  request: Request,
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
def list_branches(repo_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> List[Branch]:
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    return get_branch(repo_id, db)

@router.delete("/{repo_id}/branches/{branch_id}")
@limiter.limit("20/hour")
def delete_branch(repo_id: int, branch_id: int,
                  request: Request,
                  user: User = Depends(get_current_user),
                  csrf: bool = Depends(verify_csrf),
                  db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    branch: Branch = get_branch(repo_id, db, branch_id=branch_id)
    if branch.name == repo.default_branch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default branch"
        )
    db.delete(branch)
    db.commit()
    
    return {"status": "ok"}

@router.post("/{repo_id}/commits", response_model=CommitResponse)
@limiter.limit("100/hour")
def create_commit(repo_id: int,
                  commit_data: CommitCreate,
                  request: Request,
                  user: User = Depends(get_current_user),
                  csrf: bool = Depends(verify_csrf),
                  db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    commit_hash = generate_commit_hash(commit_data.message, user.id, datetime.utcnow())
    # Verify branch exists
    get_branch(repo_id, db, branch_id=commit_data.branch_id)
    last_commit = get_latest_commit(repo_id, commit_data.branch_id, db)
    
    commit = Commit(
        message = commit_data.message,
        author_id = user.id,
        repository_id = repo_id,
        branch_id = commit_data.branch_id,
        parent_commit_id = last_commit.id if last_commit else None,
        commit_hash = commit_hash,
    )
    
    db.add(commit)
    db.commit()
    db.refresh(commit)
    
    for file_change in commit_data.files:
        if file_change.action == "add" or file_change.action == "modify":
            file = File(
                filename=file_change.filepath.split('/')[-1],
                filepath=file_change.filepath,
                content=file_change.content,
                file_size=len(file_change.content),
                repo_id=repo_id,
                commit_id=commit.id
            )
            db.add(file)
        elif file_change.action == "delete":
            existing_file = db.query(File).filter(
                File.repo_id == repo_id,
                File.filepath == file_change.filepath
            ).first()
            if existing_file:
                db.delete(existing_file)
                
    db.commit()
    
    branch = get_branch(repo_id, db, branch_id=commit_data.branch_id)
    branch.last_commit_id = commit.id
    db.commit()
    
    return commit

@router.get("/{repo_id}/commits", response_model=List[CommitResponse])
def list_commits(repo_id: int, branch_id: Optional[int],
                 user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)
                ):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    
    if branch_id:
        commits = db.query(Commit).filter(
            Commit.repository_id == repo_id,
            Commit.branch_id == branch_id
        ).order_by(Commit.created_at.desc()).all()
    else:
        commits = db.query(Commit).filter(
            Commit.repository_id == repo_id
        ).order_by(Commit.created_at.desc()).all()
    
    return commits

@router.get("/{repo_id}/commits/{commit_id}", response_model=CommitResponse)
def get_commit(repo_id: int, commit_id: int,
               user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    commit = _get_commit(repo_id, commit_id, db)
    return commit

@router.get("/{repo_id}/files/{file_id}", response_model=FileResponse)
def get_file(repo_id: int, file_id: int,
             user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    return _get_file(repo_id, file_id, db)

@router.get("/{repo_id}/commits/{commit_id}/files", response_model=List[FileResponse])
def list_commit_files(repo_id: int, commit_id: int,
                      user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    files = get_all_files(repo_id, db, commit_id=commit_id)
    return files

@router.post("/{repo_id}/issues", response_model=IssueResponse)
def create_issue(repo_id: int, issue_data: IssueCreate,
                 user: User = Depends(get_current_user),
                 csrf: bool = Depends(verify_csrf),
                 db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    issue = Issue(
        title = issue_data.title,
        description = issue_data.description,
        author_id = user.id,
        repo_id = repo_id,
        assigned_to_id = issue_data.assigned_to_id
    )
    
    db.add(issue)
    db.commit()
    db.refresh(issue)
    
    return issue

@router.get("/{repo_id}/issues", response_model=List[IssueResponse])
def list_issues(repo_id: int, status: Optional[str],
                user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    issues = db.query(Issue).filter(
        Issue.repo_id == repo_id
    )
    if status:
        issues = issues.filter(Issue.status == status)
    issues = issues.order_by(Issue.created_at.desc()).all()
    return issues

@router.put("/{repo_id}/issues/{issue_id}", response_model=IssueResponse)
def update_issue(repo_id: int, issue_id: int,
                 issue_data: IssueUpdate, 
                 user: User = Depends(get_current_user),
                 csrf: bool = Depends(verify_csrf),
                 db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    
    issue: Issue = get_issue(repo_id, db, issue_id=issue_id)
    if issue_data.title is not None:
        issue.title = issue_data.title
    
    if issue_data.description is not None:
        issue.description = issue_data.description
        
    if issue_data.status is not None:
        if issue_data.status == "closed":
            issue.closed_at = datetime.utcnow()
        issue.status = issue_data.status
    
    if issue_data.assigned_to_id is not None:
        issue.assigned_to_id = issue_data.assigned_to_id
        
    db.commit()
    db.refresh(issue)
    return issue

@router.post("/{repo_id}/issues/{issue_id}/comments", response_model=IssueCommentResponse)
def add_comment(repo_id: int, issue_id: int, comment_data: IssueCommentCreate,
                user: User = Depends(get_current_user),
                csrf: bool = Depends(verify_csrf),
                db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    
    # Verify the issue exists
    get_issue(repo_id, db, issue_id)
    
    comment = IssueComment(
        content = comment_data.content,
        author_id = user.id,
        issue_id = issue_id
    )
    
    db.add(comment)
    db.commit()
    db.refresh(comment)
    
    return comment

@router.post("/{repo_id}/pull-requests", response_model=PullRequestResponse)
def create_pull_request(repo_id: int, pr_data: PullRequestCreate,
                        user: User = Depends(get_current_user),
                        csrf: bool = Depends(verify_csrf),
                        db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    
    # Verifies that branches exist
    get_branch(repo_id, db, branch_id=pr_data.source_branch_id) # Source
    get_branch(repo_id, db, branch_id=pr_data.target_branch_id) # Target
    
    pr = PullRequest(
        title = pr_data.title,
        description = pr_data.description,
        author_id = user.id,
        repo_id = repo_id,
        source_branch_id = pr_data.source_branch_id,
        target_branch_id = pr_data.target_branch_id
    )
    
    db.add(pr)
    db.commit()
    db.refresh(pr)
    
    return pr

@router.post("/{repo_id}/pull-requests/{pr_id}/merge")
def merge_pull_request(repo_id: int, pr_id: int,
                       user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "write", db)
    pr = get_pull_request(repo_id, pr_id, db)
    if not pr.status == "open":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Pull request is not open"
        )
        
    source_branch: Branch = get_branch(repo_id, db, branch_id=pr.source_branch_id) 
    target_branch: Branch = get_branch(repo_id, db, branch_id=pr.target_branch_id)
    
    copy_commits(source_branch, target_branch, db)
    
    pr.status = "merged"
    pr.merged_at = datetime.utcnow()
    
    db.commit()
    db.refresh(pr)
    
    return {"status": "ok"}

@router.post("/{repo_id}/collaborators", response_model=CollaboratorResponse)
def add_collaborator(repo_id: int, collab_data: CollaboratorAdd,
                     user: User = Depends(get_current_user),
                     csrf: bool = Depends(verify_csrf),
                     db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "admin", db)
    
    # Verify user exists
    user = get_user(collab_data.user_id, db)
    
    collaborator = Collaborator(
        user_id = user.id,
        repo_id = repo_id,
        permission_level = collab_data.permission_level,
    )
    
    db.add(collaborator)
    db.commit()
    db.refresh(collaborator)
    
    return collaborator

@router.delete("/{repo_id}/collaborators/{user_id}")
def remove_collaborator(repo_id: int, user_id: int, 
                        user: User = Depends(get_current_user),
                        csrf: bool = Depends(verify_csrf),
                        db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "admin", db)
    collaborator = get_collaborator(repo_id, db, user_id)
    db.delete(collaborator)
    db.commit()
    
    return {"status": "ok"}

@router.get("/{repo_id}/collaborators", response_model=List[CollaboratorResponse])
def list_collaborators(repo_id: int,
                       user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    repo = get_repo(repo_id, db)
    check_repo_access(repo, user, "read", db)
    collaborators: List[Collaborator] = get_collaborator(repo_id, db)
    return collaborators