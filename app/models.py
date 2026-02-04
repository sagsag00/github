from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Text,
    UniqueConstraint     
)
from sqlalchemy.orm import relationship
import datetime

from app.database import Base

utcnow = lambda: datetime.datetime.now(datetime.UTC)

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    
    repositories = relationship(
        "Repository",
        back_populates="owner",
        cascade="all, delete-orphan"
    )

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True, nullable=False)
    success = Column(Boolean, nullable=False)
    ip_address = Column(String, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)  # JWT ID
    revoked_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    
class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_owner_repo_name"),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, default="")
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_private = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    default_branch = Column(String, default="main")
    
    owner = relationship("User", back_populates="repositories")
    
    branches = relationship(
        "Branch",
        back_populates="repository",
        cascade="all, delete-orphan"
    )
    
    commits = relationship(
        "Commit",
        back_populates="repository",
        cascade="all, delete-orphan",
        order_by="Commit.created_at.desc()"
    )
    
    files = relationship(
        "File",
        back_populates="repository",
        cascade="all, delete-orphan"
    )
    
    issues = relationship(
        "Issue",
        back_populates="repository",
        cascade="all, delete-orphan"
    )
    
    pull_requests = relationship(
        "PullRequest",
        back_populates="repository",
        cascade="all, delete-orphan"
    )
    
    collaborators = relationship(
        "Collaborator",
        back_populates="repository",
        cascade="all, delete-orphan"
    )

class Branch(Base):
    __tablename__ = "branches"   
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    created_at = Column(DateTime, default=utcnow)
    last_commit_id = Column(Integer,
                            ForeignKey("commits.id", use_alter=True),
                            nullable=True)
    
    repository = relationship("Repository", back_populates="branches")
    
    commits = relationship(
        "Commit",
        back_populates="branch",
        cascade="all, delete-orphan",
        foreign_keys="Commit.branch_id"
    )

class Commit(Base):
    __tablename__ = "commits"
    
    id = Column(Integer, primary_key=True, index=True)
    message = Column(String(255), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
    repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    branch_id = Column(Integer, ForeignKey("branches.id"))
    parent_commit_id = Column(Integer, ForeignKey("commits.id"), nullable=True)
    commit_hash = Column(String, unique=True)
    created_at = Column(DateTime, default=utcnow)
    
    author = relationship("User")
    repository = relationship("Repository", back_populates="commits")
    branch = relationship("Branch", back_populates="commits", foreign_keys=[branch_id])
    
    files = relationship(
        "File",
        back_populates="commit",
        cascade="all, delete-orphan"
    )

    parent = relationship("Commit", remote_side=[id])
    
class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False)
    content = Column(Text, nullable=True)
    file_size = Column(Integer)
    repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    commit_id = Column(Integer, ForeignKey("commits.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    repository = relationship("Repository", back_populates="files")
    commit = relationship("Commit", back_populates="files")
    
class Issue(Base):
    __tablename__ = "issues"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="open")
    author_id = Column(Integer, ForeignKey("users.id"))
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    closed_at = Column(DateTime, nullable=True)
    
    author = relationship("User", foreign_keys=[author_id])
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    
    repository = relationship("Repository", back_populates="issues")
    
    comments = relationship(
        "IssueComment",
        back_populates="issue",
        cascade="all, delete-orphan"
    )
    
class IssueComment(Base):
    __tablename__ = "issue_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
    issue_id = Column(Integer, ForeignKey("issues.id"))
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    author = relationship("User")
    issue = relationship("Issue", back_populates="comments")
    
class PullRequest(Base):
    __tablename__ = "pull_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(String, default="open")
    author_id = Column(Integer, ForeignKey("users.id"))
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    source_branch_id = Column(Integer, ForeignKey("branches.id"))
    target_branch_id = Column(Integer, ForeignKey("branches.id"))
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    merged_at = Column(DateTime, nullable=True)
    
    author = relationship("User")
    repository = relationship("Repository", back_populates="pull_requests")
    
    source_branch = relationship("Branch", foreign_keys=[source_branch_id])
    target_branch = relationship("Branch", foreign_keys=[target_branch_id])
    
class Collaborator(Base):
    __tablename__ = "collaborators"
    __table_args__ = (
       UniqueConstraint("user_id", "repo_id", name="uq_user_repo"),
   )
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    permission_level = Column(String, default="read")
    added_at = Column(DateTime, default=utcnow)
    
    user = relationship("User")
    repository = relationship("Repository", back_populates="collaborators")