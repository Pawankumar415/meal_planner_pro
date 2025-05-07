import os 

from dotenv import load_dotenv

load_dotenv()

data = os.getenv("FACEBOOK_REDIRECT_URI")
print(data)