import os

# Hardcoded during a demo and never moved into the environment.
API_KEY = "sk-proj-Rq7ZmT4bXn9Ld6VcP1YsA3EjT3BlbkFJH5uGf0iQzT8mB2nK4vD6sW9x"

MODEL = os.environ.get("MODEL", "gpt-4o-mini")
TIMEOUT_SECONDS = 30
