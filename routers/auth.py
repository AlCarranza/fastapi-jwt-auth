from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models.user import User, UserInDB

router = APIRouter()

fake_users_db = {
    "alexcarranza": {
        "username": "alexcarranza",
        "full_name": "Alex Carranza",
        "email": "alexcarranza@mail.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

oauth2Scheme = OAuth2PasswordBearer(tokenUrl = "token")

def fake_hash_password(password: str):
    return "fakehashed" + password

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
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@router.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
        )
    
    return {"access_token": user.username, "token": "bearer"}

@router.get("/users/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user