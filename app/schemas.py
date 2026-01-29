from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    
class UserLogin(BaseModel):
    username: str
    password: str
    
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    
    class Config:
        from_attributes = True
        
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    
class StatusResponse(BaseModel):
    status: str
    csrf_token: Optional[str] = None
    
class RepositoryCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_private: bool = False
    default_branch: str = "main"
    
class RepositoryUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_private: Optional[bool] = None
    default_branch: Optional[str] = None
    
class RepositoryResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    owner_id: int
    is_private: bool
    created_at: datetime
    updated_at: datetime
    default_branch: str
    
    class Config:
        orm_mode = True
    
class BranchCreate(BaseModel):
    name: str
    source_branch_id: Optional[int] = None
    
class BranchResponse(BaseModel):
    id: int
    name: str
    repo_id: int
    created_at: datetime
    last_commit_id: Optional[int]
    
    class Config:
        orm_mode = True

class FileChange(BaseModel):
    filepath: str
    content: str
    action: str

class CommitCreate(BaseModel):
    message: str
    branch_id: int
    files: List[FileChange]
    
class CommitResponse(BaseModel):
    id: int
    message: int
    author_id: int
    repo_id: int
    branch_id: int
    commit_hash: str
    created_at: datetime
    parent_commit_id: Optional[int]
    
    class Config:
        orm_mode = True

class FileResponse(BaseModel):
    id: int
    filename: str
    filepath: str
    content: str
    file_size: int
    repo_id: int
    commit_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True
        
class IssueCreate(BaseModel):
    title: str
    description: Optional[str] = None
    assigned_to_id: Optional[int] = None
    
class IssueUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    
class IssueResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: str
    author_id: int
    repo_id: int
    assigned_to_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    
    class Config:
        orm_mode = True

class IssueCommentCreate(BaseModel):
    content: str

class IssueCommentResponse(BaseModel):
    id: int
    content: str
    author_id: int
    issue_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True
        
class PullRequestCreate(BaseModel):
    title: str
    description: Optional[str] = None
    source_branch_id: int
    target_branch_id: int
    
class PullRequestUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    
class PullRequestResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: str
    author_id: int
    repo_id: int
    source_branch_id: int
    target_branch_id: int
    created_at: datetime
    updated_at: datetime
    merged_at: Optional[datetime]
    
    class Config:
        orm_mode = True
        
class CollaboratorAdd(BaseModel):
    user_id: int
    permission_level: str = "read"

class CollaboratorResponse(BaseModel):
    id: int
    user_id: int
    repo_id: int
    permission_level: str
    added_at: datetime
    
    class Config:
        orm_mode = True