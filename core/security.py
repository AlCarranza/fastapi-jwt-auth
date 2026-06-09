from passlib.context import CryptContext


"""
You might think, why we don't use SHA256?, we intentionally want to use bcrypt because it is slow
brute force is a upside, attackers might try billion of passwords per second with sha256.

So bcypt is intentionally slow
"""
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)