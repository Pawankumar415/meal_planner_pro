import os 

from dotenv import load_dotenv

load_dotenv()

data = os.getenv("GEMINI_API_KEY")
print(data)