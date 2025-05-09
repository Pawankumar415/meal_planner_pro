# from __future__ import annotations

# import time
# from typing import Any
# from decouple import config
# from jose import JWTError,jwt


# JWT_SECRET = config('secret')
# JWT_ALGORITHM = config('algorithm')


# def token_response(token: str):
#     return {
#         "access_token": token
#     }


# def signJWT(user_id: str, user_type: str) -> tuple[Any, float]:
#     expiration_time = time.time() + 1 * 24 * 60 * 60
#     payload = {
#         "user_id": user_id,
#         "user_type": user_type,
#         "exp": expiration_time
#     }
#     token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

#     return token, expiration_time


# def decodeJWT(token: str) -> Any | None:
#     try:
#         decoded_token = jwt.decode(token, JWT_SECRET, algorithm=JWT_ALGORITHM)
#         if decoded_token.get("exp") and decoded_token["exp"] < time.time():
#             return None
#             # Check if the necessary claims are present
#         if "user_id" not in decoded_token or "user_type" not in decoded_token:
#             return None
#         return decoded_token
#     except JWTError:
#         return None




from __future__ import annotations

import time
from typing import Any
from decouple import config
from jose import JWTError, jwt

JWT_SECRET = config('secret')
JWT_ALGORITHM = config('algorithm')

def token_response(token: str):
    return {
        "access_token": token
    }

def signJWT(user_id: str, user_type: str) -> tuple[Any, float]:
    expiration_time = time.time() + 1 * 24 * 60 * 60
    payload = {
        "user_id": user_id,
        "user_type": user_type,
        "exp": expiration_time
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expiration_time

def decodeJWT(token: str) -> Any | None:
    # print(f"Token received in decodeJWT: {token}") 
    try:
        
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded_token.get("exp") and decoded_token["exp"] < time.time():
            return None
        # Check if the necessary claims are present
        if "user_id" not in decoded_token or "user_type" not in decoded_token:
            return None
        return decoded_token
    except JWTError as e:
        print(f"JWTError in decodeJWT: {e}") 
        return None