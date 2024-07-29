## Submitted by Sanjaya Deshappriya Gunawardena

from redis import Redis
from typing import Union , Dict , List
from fastapi import FastAPI , Query
from pydantic import BaseModel
import bcrypt
from fastapi import HTTPException


redis = Redis(host="redis", port=6379, decode_responses=True)

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
    # Store mapping from username to user ID
    redis.set(f"username:{user.username}", user_id)
    return {"success": True, user_id: user_id}

# Get User Followers
"""
    Get the followers of a specific user.
    
    Parameters:
    - user_id (int): The ID of the user.
    - start (int): The start index for pagination (default 0).
    - stop (int, optional): The stop index for pagination. If not provided, all followers will be retrieved.
    
    Returns:
    - List[int]: A list of user IDs who follow the specified user.
    """
@app.get("/user/{user_id}/followers", tags=["Users"])
async def get_user_followers(user_id: int, start: int = 0, stop: int = None) -> List[int]:
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

# Get user following
"""
    Get the users followed by a specific user.
    
    Parameters:
    - user_id (int): The ID of the user.
    - start (int): The start index for pagination (default 0).
    - stop (int): The stop index for pagination (default 10).
    
    Returns:
    - List[int]: A list of user IDs that the specified user follows.
    """
@app.get("/user/{user_id}/following", tags=["Users"])
async def get_user_following(user_id: int, start: int = Query(0, ge=0), stop: int = Query(10, ge=0)) -> List[int]:
    following_key = f"user:{user_id}:following"
    following = redis.zrange(following_key, start, stop)
    return [int(following_id) for following_id in following]

#Unfollow a user
"""
    Unfollow a user.
    
    Parameters:
    - user_id (int): The ID of the user.
    - target_user_id (int): The ID of the user to unfollow.
    
    Returns:
    - dict: A message indicating whether the operation was successful.
    """
@app.delete("/user/{user_id}/following/{target_user_id}", tags=["Users"])
async def unfollow_user(user_id: int, target_user_id: int):
    following_key = f"user:{user_id}:following"
    redis.zrem(following_key, target_user_id)
    return {"message": "User unfollowed successfully"}


#Create a post
"""
    Create a new post.
    
    Parameters:
    - user_id (int): The ID of the user creating the post.
    - post (NewPost): The content of the post.
    
    Returns:
    - dict: A message indicating whether the operation was successful and the ID of the created post.
    """
from datetime import datetime

class NewPost(BaseModel):
    content: str

@app.post("/post/", tags=["Posts"])
async def create_post(user_id: int, post: NewPost):
    post_id = redis.incr("seq:post")
    post_info = {
        "user_id": user_id,
        "content": post.content,
        "timestamp": datetime.now().isoformat()
    }
    redis.hmset(f"post:{post_id}", post_info)
    redis.lpush(f"user:{user_id}:posts", post_id)
    return {"success": True, "post_id": post_id}

#Getting the post content
"""
    Get posts of a user with pagination.
    
    Parameters:
    - user_id (int): The ID of the user.
    - start (int): The start index for pagination (default 0).
    - stop (int): The stop index for pagination (default 10).
    
    Returns:
    - List[Dict[str, Union[int, str]]]: A list of dictionaries containing post details.
    """
@app.get("/user/{user_id}/posts", tags=["Posts"])
async def get_user_posts(user_id: int, start: int = Query(0, ge=0), stop: int = Query(10, ge=0)) -> List[Dict[str, Union[int, str]]]:
    user_posts_key = f"user:{user_id}:posts"
    post_ids = redis.lrange(user_posts_key, start, stop)
    posts = []
    for post_id in post_ids:
        post_info = redis.hgetall(f"post:{post_id}")
        posts.append({
            "post_id": int(post_id),
            "user_id": int(post_info["user_id"]),
            "content": post_info["content"],
            "timestamp": post_info["timestamp"]
        })
    return posts

#Checking the authentication
"""
    Authenticate a user.
    
    Parameters:
    - user_id (int): The ID of the user.
    - password (str): The password provided by the user.
    
    Returns:
    - dict: A message indicating whether the authentication was successful.
    """
@app.post("/user/authenticate", tags=["Authentication"])
async def authenticate_user(user_id: int, password: str):
    user_key = f"user:{user_id}"
    user_info = redis.hgetall(user_key)
    if not user_info:
        raise HTTPException(status_code=404, detail="User not found")
    stored_password = user_info.get("password")
    if not stored_password or not check_password(password.encode(), stored_password.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"message": "Authentication successful"}


# When searching for a user by username
"""
    Get user information by username.
    
    Parameters:
    - username (str): The username of the user.
    
    Returns:
    - User: The user object retrieved by username.
    """
@app.get("/user/{username}", response_model=User)
async def get_user_by_username(username: str):
    user_id = redis.get(f"username:{username}")
    if user_id is None:
        raise HTTPException(status_code=404, detail="User not found")
    user_data = redis.hgetall(f"user:{user_id}")
    return user_data
