from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models.user import User, UserInDB, UserCreate

from core import security

from jose import JWTError, jwt

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
        return UserInDB(**db[username])
    return None

# Here we use the class OAuth2PasswordBearer which is the tool provided by OAuth2 to handle the
# authentication and security. It is designed to have the backend in a server and the auth in other,
# but we'll be using the same

# In the instance we pass the parameter tokenUrl which contains the URL that the cliend will use to send
# the username and password in order to get a token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl= "token")


"""
This will go and look in the request for that Authorization header, check if the value is Bearer plus some token,
and will return the token as a str

If it doesn't see an Authorization header, or the value doesn't have a Bearer token, will respond with 401 (UNAUTHORIZED)
"""
@router.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            security.SECRET_KEY,
            algorithms=[security.ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(
        fake_users_db,
        username
    )

    if user is None:
        raise credentials_exception

    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Inactive user"
        )
    return current_user

@router.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password")
    user = UserInDB(**user_dict)

    if not security.verify_password(
        form_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = security.create_access_token(
        data={
            "sub": user.username
        }
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

"""
This proves your dependency chain works:

/users/me
    ↓
get_current_active_user
    ↓
get_current_user
    ↓
jwt.decode()
    ↓
extract "sub"
    ↓
get_user()
"""
@router.get("/users/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@router.post("/register", response_model=User)
async def register(user: UserCreate):

    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    hashed_password = security.hash_password(user.password)

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