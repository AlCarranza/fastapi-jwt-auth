from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from models import user

app = FastAPI()

app.include_router(user.router)

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
@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2Scheme)]):
    return {"token": token}
