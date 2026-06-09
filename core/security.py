from passlib.context import CryptContext


"""
bcrypt is intentionally computationally expensive.

Algorithms such as SHA256 are designed to be very fast,
which makes them unsuitable for password storage because
attackers can perform billions of guesses per second.

bcrypt slows down password verification on purpose,
making brute-force and dictionary attacks significantly
more expensive.

Passwords should be hashed with bcrypt (or Argon2)
before being stored in the database.
"""
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)