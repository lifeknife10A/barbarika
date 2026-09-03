from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import health, events, heartbeat

app = FastAPI(title="Barbarika Sentry", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(events.router)
app.include_router(heartbeat.router)
