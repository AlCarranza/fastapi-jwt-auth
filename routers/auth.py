from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models.user import User, UserInDB, UserCreate

from core.security import (
    hash_password,
    verify_password
)

router = APIRouter()

fake_users_db = {
    "alexcarranza": {
        "username": "alexcarranza",
        "full_name": "Alex Carranza",
        "email": "alexcarranza@mail.com",
        "hashed_password": "$2b$12$VikySdDCtXflFAps0ybeEul7JSsqnDM12gkSCnthUmhloAC.5n67S", # secret
        "disabled": False
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$4yx/m9JLDbPAL/d9v0SztOHzaf74W8TJVNg5QncxQ1CeHnTKOUhAq", # secret2
        "disabled": True,
    },
}

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user

# Here we use the class OAuth2PasswordBearer which is the tool provided by OAuth2 to handle the
# authentication and security. It is designed to have the backend in a server and the auth in other,
# but we'll be using the same

# In the instance we pass the parameter tokenUrl which contains the URL that the cliend will use to send
# the username and password in order to get a token

oauth2Scheme = OAuth2PasswordBearer(tokenUrl= "token")


"""
This will go and look in the request for that Authorization header, check if the value is Bearer plus some token,
and will return the token as a str

If it doesn't see an Authorization header, or the value doesn't have a Bearer token, will respond with 401 (UNAUTHORIZED)
"""
@router.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2Scheme)]):
    return {"token": token}

async def get_current_user(token: Annotated[str, Depends(oauth2Scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(
            status_code=401, 
            detail="Inactive user"
        )
    return current_user

@router.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password")
    user = UserInDB(**user_dict)

    if not verify_password(
        form_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
        )
    
    return {"access_token": user.username, "token_type": "bearer"}

"""
This proves your dependency chain works:

/users/me
    ↓
get_current_active_user
    ↓
get_current_user
    ↓
fake_decode_token
"""
@router.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@router.post("/register", response_model=User)
async def register(user: UserCreate):

    if user.username in fake_users_db:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )
    
    hashed_password = hash_password(user.password)

    fake_users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "disabled": False,
    }

    return {
    "username": user.username,
    "email": user.email,
    "full_name": user.full_name,
    "disabled": False,
}

"""
Testing purposes: SHould not show passwords
"""
@router.get("/debug/users")
async def debug_users():
    return fake_users_db