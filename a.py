from core.config import get_settings

settings = get_settings()

print(settings.SECRET)       # Output from .env
print(settings.ENVIRONMENT)      # dev or prod
print(settings.DEV_DATABASE_URL) # Dev DB URL from .env



# note registration fixed move to login



# import secrets

# data = secrets.token_hex(32)
# print(data)