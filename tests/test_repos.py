import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime

from app.main import app
from app.database import Base, get_db
from app.models import User, Repository, Branch, Commit, File, Issue, IssueComment, PullRequest, Collaborator
from app.password import get_password_hash

SQLALCHEMY_DATABASE_URL = "sqlite:///./data/test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()
        
app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database session for each test"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    
@pytest.fixture
def test_user(db_session: Session) -> User:
    """Create a test user"""
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=get_password_hash("TestPassword123!")
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def test_user2(db_session: Session) -> User:
    """Create a second test user"""
    user = User(
        username="testuser2",
        email="test2@example.com",
        password_hash=get_password_hash("TestPassword123!")
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def auth_headers(test_user: User):
    """Get authentication headers"""
    response = client.post(
        "/auth/login",
        json={"username": "testuser", "password": "TestPassword123!"}
    )
    csrf_token = response.json()["csrf_token"]
    return {"X-CSRF-Token": csrf_token}

@pytest.fixture
def auth_headers_user2(test_user2: User):
    """Get authentication headers for the second user"""
    response = client.post(
        "/auth/login",
        json={"username": "testuser2", "password": "TestPassword123!"}
    )
    csrf_token = response.json()["csrf_token"]
    return {"X-CSRF-Token": csrf_token}

@pytest.fixture
def test_repo(db_session: Session, test_user: User) -> Repository:
    """Create a test repo"""
    repo = Repository(
        name="test-repo",
        description="Test repository",
        owner_id=test_user.id,
        is_private=False,
        default_branch="main"
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)
    
    branch = Branch(
        name="main",
        repo_id=repo.id
    )
    db_session.add(branch)
    db_session.commit()
    
    return repo

@pytest.fixture
def test_private_repo(db_session: Session, test_user: User) -> Repository:
    """Create a test private repository"""
    repo = Repository(
        name="private-repo",
        description="Private repository",
        owner_id = test_user.id,
        is_private=True,
        default_branch="main"
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)
    
    branch = Branch(
        name="main",
        repo_id=repo.id
    )
    db_session.add(branch)
    db_session.commit()
    
    return repo

# ==================== REPOSITORY TESTS ====================

class TestRepositoryEndpoints:
    def test_create_repository(self, db_session: Session, test_user: User, auth_headers):
        """Test creating a new repository"""
        response = client.post(
            "/repos/",
            json={
                "name": "new-repo",
                "description": "A new repository",
                "is_private": False,
                "default_branch": "main"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "new-repo"
        assert data["description"] == "A new repository"
        assert data["owner_id"] == test_user.id
        assert data["is_private"] == False
        
    def test_create_duplicate_repository(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating a repository with duplicate name"""
        response = client.post(
            "/repos/",
            json={
                "name": "test-repo",
                "description": "Duplicate",
                "is_private": False,
                "default_branch": "main"
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "already have a repository" in response.json()["detail"]
        
    def test_list_repositories(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test listing user repositories"""
        response = client.get("/repos/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(repo["name"] == "test-repo" for repo in data)
        
    def test_get_repository(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test getting a specific repository"""
        response = client.get(f"/repos/{test_repo.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-repo"
        assert data["id"] == test_repo.id
        
    def test_get_private_repository_unauthorized(self, db_session: Session,
                                                 test_user: User,
                                                 test_user2: User,
                                                 test_private_repo: Repository,
                                                 auth_headers,
                                                 auth_headers_user2):
        """Test accessing private repository without permission"""
        response = client.get(f"/repos/{test_private_repo.id}")
        assert response.status_code == 403
        
    def test_update_repository(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test updating repository details"""
        response = client.put(
            f"/repos/{test_repo.id}",
            json={
                "name": "updated-repo",
                "description": "Updated description"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "updated-repo"
        assert data["description"] == "Updated description"
        
    def test_update_repository_unauthorized(self, db_session: Session,
                                                 test_user: User,
                                                 test_user2: User,
                                                 test_repo: Repository,
                                                 auth_headers,
                                                 auth_headers_user2):
        """Test updating a repository without permission"""
        response = client.put(
            f"/repos/{test_repo.id}",
            json={"name": "hacked-repo"},
            headers=auth_headers_user2
        )
        assert response.status_code == 403
        
    def test_delete_repository(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers,):
        """Test deleting a repository"""
        response = client.delete(
            f"/repos/{test_repo.id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        
        verify_response = client.get(f"/repos/{test_repo.id}")
        assert verify_response.status_code == 404
        
    def test_delete_repository_unauthorized(self, db_session: Session,
                                                 test_user: User,
                                                 test_user2: User,
                                                 test_repo: Repository,
                                                 auth_headers,
                                                 auth_headers_user2):
        """Testing deleting a repository without permission"""
        response = client.delete(
            f"/repos/{test_repo.id}",
            headers=auth_headers_user2
        )
        assert response.status_code == 403
        
# ==================== BRANCH TESTS ====================

class TestBranchEndpoints:
    def test_create_branch(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating a new branch"""
        response = client.post(
            f"/repos/{test_repo.id}/branches",
            json={"name": "feature-branch"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "feature-branch"
        assert data["repo_id"] == test_repo.id
        
    def test_create_duplicate_branch(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating a branch with duplicate name"""
        client.post(
            f"/repos/{test_repo.id}/branches",
            json={"name": "dev"},
            headers=auth_headers
        )
        
        response = client.post(
            f"repos/{test_repo.id}/branches",
            json={"name": "dev"},
            headers=auth_headers
        )
        assert response.status_code == 400
        
    def test_list_branches(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test listing repository branches"""
        client.post(
            f"/repos/{test_repo.id}/branches",
            json={"name": "dev"},
            headers=auth_headers
        )
        
        response = client.get(f"/repos/{test_repo.id}/branches")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2
        branches_names = [branch["name"] for branch in data]
        assert "main" in branches_names
        assert "dev" in branches_names
        
    def test_delete_branch(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test deleting a branch"""
        
        create_response = client.post(
            f"/repos/{test_repo.id}/branches",
            json={"name": "temp-branch"},
            headers=auth_headers
        )
        branch_id = create_response.json()["id"]
        
        response = client.delete(
            f"/repos/{test_repo.id}/branches/{branch_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        
    def test_delete_default_branch(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test preventing deletion of default branch"""
        
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        response = client.delete(
            f"/repos/{test_repo.id}/branches/{main_branch['id']}",
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "default branch" in response.json()["detail"]
        
# ==================== COMMIT TESTS ====================

class TestCommitEndpoints:
    
    def test_create_commit(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating a commit"""
        
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        response = client.post(
            f"/repos/{test_repo.id}/commits",
            json={
                "message": "Initial commit",
                "branch_id": main_branch["id"],
                "files": [
                    {
                        "filepath": "README.md",
                        "content": "# Test Repo",
                        "action": "add"
                    }
                ]
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Initial commit"
        assert data["author_id"] == test_user.id
        
    def test_list_commits(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test listing commits"""
        
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        client.post(
            f"/repos/{test_repo.id}/commits",
            json={
                "message": "Test commit",
                "branch_id": main_branch["id"],
                "files": []
            },
            headers=auth_headers
        )
        
        response = client.get(f"/repos/{test_repo.id}/commits?branch_id={main_branch['id']}")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        
    def test_get_commit(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test getting a specific commit"""
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        create_response = client.post(
            f"/repos/{test_repo.id}/commits",
            json={
                "message": "Test commit",
                "branch_id": main_branch["id"],
                "files": []
            },
            headers=auth_headers
        )
        commit_id = create_response.json()["id"]
        
        response = client.get(f"/repos/{test_repo.id}/commits/{commit_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == commit_id
        
# ==================== FILE TESTS ====================

class TestFileEndpoints:
    def test_list_commit_files(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test listing files in a commit"""
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        create_response = client.post(
            f"/repos/{test_repo.id}/commits",
            json={
                "message": "Add files",
                "branch_id": main_branch["id"],
                "files": [
                    {"filepath": "file1.txt", "content": "Content 1", "action": "add"},
                    {"filepath": "file2.txt", "content": "Content 2", "action": "add"}
                ]
            },
            headers=auth_headers
        )
        commit_id = create_response.json()["id"]
        
        response = client.get(f"/repos/{test_repo.id}/commits/{commit_id}/files")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        
# ==================== ISSUE TESTS ====================

class TestIssueEndpoints:
    
    def test_create_issue(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating an issue"""
        response = client.post(
            f"/repos/{test_repo.id}/issues",
            json={
                "title": "Bug report",
                "description": "Something is broken"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Bug report"
        assert data["status"] == "open"
        
    def test_list_issues(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test listing issues"""
        client.post(
            f"/repos/{test_repo.id}/issues",
            json={"title": "Test issue"},
            headers=auth_headers
        )
        
        response = client.get(f"/repos/{test_repo.id}/issues")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        
    def test_update_issue(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test updating an issue"""
        create_response = client.post(
            f"/repos/{test_repo.id}/issues",
            json={"title": "Original title"},
            headers=auth_headers
        )
        issue_id = create_response.json()["id"]
        
        # Update issue
        response = client.put(
            f"/repos/{test_repo.id}/issues/{issue_id}",
            json={
                "title": "Updated title",
                "status": "closed"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated title"
        assert data["status"] == "closed"
        assert data["closed_at"] is not None
        
    def test_add_issue_comment(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test adding a comment to an issue"""
        create_response = client.post(
            f"/repos/{test_repo.id}/issues",
            json={"title": "Test issue"},
            headers=auth_headers
        )
        issue_id = create_response.json()["id"]
        
        response = client.post(
            f"/repos/{test_repo.id}/issues/{issue_id}/comments",
            json={"content": "This is a comment"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["content"] == "This is a comment"

# ==================== PULL REQUEST TESTS ====================

class TestPullRequestEndpoints:
    
    def test_create_pull_request(self, db_session: Session, test_user: User, test_repo: Repository, auth_headers):
        """Test creating a pull request"""
        feature_response = client.post(
            f"/repos/{test_repo.id}/branches",
            json={"name": "feature"},
            headers=auth_headers
        )
        feature_branch_id = feature_response.json()["id"]
        
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch_id = next(b["id"] for b in branches if b["name"] == "main")
        
        response = client.post(
            f"/repos/{test_repo.id}/pull-requests",
            json={
                "title": "Feature PR",
                "description": "Adding new feature",
                "source_branch_id": feature_branch_id,
                "target_branch_id": main_branch_id
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Feature PR"
        assert data["status"] == "open"

# ==================== COLLABORATOR TESTS ====================

class TestCollaboratorEndpoints:
    
    def test_add_collaborator(self, db_session: Session, test_user: User, test_user2: User, test_repo: Repository, auth_headers):
        """Test adding a collaborator"""
        response = client.post(
            f"/repos/{test_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "write"
            },
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_user2.id
        assert data["permission_level"] == "write"
        
    def test_list_collaborators(self, db_session: Session, test_user: User, test_user2: User, test_repo: Repository, auth_headers):
        """Test listing collaborators"""
        client.post(
            f"/repos/{test_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "read"
            },
            headers=auth_headers
        )
        
        response = client.get(f"/repos/{test_repo.id}/collaborators")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        
    def test_remove_collaborator(self, db_session: Session, test_user: User, test_user2: User, test_repo: Repository, auth_headers):
        """Test removing a collaborator"""
        client.post(
            f"/repos/{test_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "read"
            },
            headers=auth_headers
        )
        
        response = client.delete(
            f"/repos/{test_repo.id}/collaborators/{test_user2.id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        
    def test_collaborator_access(self, db_session: Session,
                                 test_user: User, test_user2: User,
                                 test_private_repo: Repository,
                                 auth_headers, auth_headers_user2
                                 ):
        """Test collaborator can access private repo"""
        response = client.get(f"/repos/{test_private_repo.id}")
        assert response.status_code == 403
        
        fresh_auth = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPassword123!"}
        )
        fresh_headers = {"X-CSRF-Token": fresh_auth.json()["csrf_token"]}
        
        response = client.post(
            f"/repos/{test_private_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "read"
            },
            headers=fresh_headers
        )
        assert response.status_code == 200
        
        response = client.get(f"/repos/{test_private_repo.id}/collaborators", headers=fresh_headers)
        assert response.status_code == 200
        collaborators = response.json()
        assert any(c["user_id"] == test_user2.id for c in collaborators)

# ==================== PERMISSION TESTS ====================

class TestPermissions:
    
    def test_write_permission_required_for_commit(self, db_session: Session,
                                 test_user: User, test_user2: User,
                                 test_repo: Repository,
                                 auth_headers, auth_headers_user2
                                 ):
        """Test that write permission is required to create commits"""
        client.post(
            f"/repos/{test_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "read"
            },
            headers=auth_headers
        )
        
        branches = client.get(f"/repos/{test_repo.id}/branches").json()
        main_branch = next(b for b in branches if b["name"] == "main")
        
        response = client.post(
            f"/repos/{test_repo.id}/commits",
            json={
                "message": "Unauthorized commit",
                "branch_id": main_branch["id"],
                "files": []
            },
            headers=auth_headers_user2
        )
        assert response.status_code == 403
        
    def test_admin_permission_required_for_settings(self, db_session: Session,
                                 test_user: User, test_user2: User,
                                 test_repo: Repository,
                                 auth_headers, auth_headers_user2
                                 ):
        """Test that admin permission is required to update repository settings"""
        client.post(
            f"/repos/{test_repo.id}/collaborators",
            json={
                "user_id": test_user2.id,
                "permission_level": "write"
            },
            headers=auth_headers
        )
        
        response = client.put(
            f"/repos/{test_repo.id}",
            json={"name": "hacked-name"},
            headers=auth_headers_user2
        )
        assert response.status_code == 403

if __name__ == "__main__":
    pytest.main([__file__, "-v"])