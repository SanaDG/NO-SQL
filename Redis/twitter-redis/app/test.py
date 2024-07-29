from redis import Redis
from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel
import bcrypt

from fastapi import HTTPException

redis = Redis(host="redis", port=8001, decode_responses=True)

class NewUser(BaseModel):
    username: str
    password: Union[str, None] = None


class User(BaseModel):
    id: int
    username: str
    follower_count: int
    following_count: int
    following: list[int]
    followers: list[int]


tags_metadata = [
    {
        "name": "Users",
        "description": "Operations with users.",
    },
]

app = FastAPI(openapi_tags=tags_metadata)

# API Endpoints


## Users
### Create User
@app.post("/user/", tags=["Users"])
async def create_user(user: NewUser):
    user_id = redis.incr("seq:user")
    hashed_password = get_hashed_password(user.password.encode())
    user_info = {
        "id": user_id,
        "username": user.username,
        "password": hashed_password,
        "follower_count": 0,
        "following_count": 0,
    }
    redis.hmset(f"user:{user_id}", user_info)
    return {"success": True, user_id: user_id}


# Get User Followers
@app.get("/user/{user_id}/followers", tags=["Users"])
async def get_user_followers(user_id: int, start: int = 0, stop: int = -1) -> List[int]:
    user_key = f"user:{user_id}"
    if not redis.exists(user_key):
        raise HTTPException(status_code=404, detail="User not found")

    # Get followers using ZRANGE with start and stop parameters for pagination
    followers = redis.zrange(user_key + ":followers", start, stop)

    return [int(follower) for follower in followers]

def get_hashed_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())


def check_password(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)
