#https://stackoverflow.com/questions/79776559/passlib-bcrypt-not-working-when-deployed-to-render-valueerror-password-cannot
import hashlib
import bcrypt

_BCRYPT_ROUNDS = 12

def _sha256_hexdigest_bytes(password: str) -> bytes:
    return hashlib.sha256(password.encode()).hexdigest().encode()

def get_password_hash(password: str) -> str:
    """Hash password using bcrypt of SHA256-hexdigest(password).
    
    Returns a standart bcrypt hash string.
    """
    prehashed = _sha256_hexdigest_bytes(password)
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(prehashed, salt)
    
    return hashed.decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash.
    
    Tries legacy prehashed mode first (sha256-hexdigest -> bcrypt). If that fails,
    falls back to checking plain bcrypt (no pre-hash). Any ValueError from bcrypt
    (e.g., due to >72 byte inputs in plain mode) is treated as failed check.
    """
    hp_bytes = hashed_password.encode()
    
    # Preferred / legacy-compatible path
    prehashed = _sha256_hexdigest_bytes(plain_password)
    if bcrypt.checkpw(prehashed, hp_bytes):
        return True
    
    # Fallback
    try:
        return bcrypt.checkpw(plain_password.encode(), hp_bytes)
    except ValueError:
        return False
    
    
    