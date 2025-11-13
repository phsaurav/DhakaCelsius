"""
Main entry point for this FastAPI Project
"""

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.weather.api import weather
from app.version import __version__
from core import config
from core.logger import Logger

app = FastAPI(title=config.cfg.title, version=__version__)
Logger.setup(app=app, json_format=True)

# CORS
if not config.cfg.prod:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.get("/")
def root():
    """
    Welcome endpoint with basic navigation information
    """
    return {
        "message": "🌡️ Welcome to DhakaCelsius!",
        "description": "Your pocket thermometer for Dhaka city",
        "status": "Server is running smoothly",
        "documentation": "Visit /docs to explore our API",
        "tip": "Try our /hello endpoint to check Dhaka's current temperature 🔥",
    }


app.include_router(weather.router)

if __name__ == "__main__":
    uvicorn.run(app, log_level=config.cfg.fastapi_log_level)
