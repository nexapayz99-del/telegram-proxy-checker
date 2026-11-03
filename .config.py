import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CONCURRENCY = int(os.getenv("CONCURRENCY", 500))
TIMEOUT = int(os.getenv("TIMEOUT", 8))
TEST_URL = os.getenv("TEST_URL", "http://httpbin.org/ip")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN is missing! Set it in your .env file.")
  
