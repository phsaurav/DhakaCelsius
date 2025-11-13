"""
Weather Service Module for fetching and processing weather data from OpenWeatherMap API.
"""

import datetime
import socket

import requests
from app.version import __version__

from app.weather.schemas import (
    HealthResponseSchema,
    TemperatureData,
    WeatherResponseSchema,
)
from core.config import cfg
from core.constants import Constants
from core.error import AppError, APIError
from core.logger import Logger


class WeatherService:
    """Service for fetching and processing weather data from external weather APIs."""

    def __init__(self):
        """
        Initialize the weather service with configuration from constants.
        """
        self.base_url = Constants.weather_api_url
        self.units = Constants.weather_api_units
        self.api_key = Constants.weather_api_key
        self.timeout = Constants.api_timeout

        if not self.api_key:
            Logger.error("Weather API key not configured")
            raise AppError(
                "Weather API key not configured. Check environment variables or configuration."
            )

    def get_weather_data(self, city: str = "Dhaka") -> TemperatureData:
        """
        Fetch weather data for a city from OpenWeatherMap API.

        """
        Logger.info(f"Fetching weather data for {city}")
        params = {"q": city, "appid": self.api_key, "units": self.units}

        try:
            response = requests.get(self.base_url, params=params, timeout=self.timeout)
            response.raise_for_status()

            weather_data = response.json()

            Logger.debug(
                f"Weather data received for {city}",
                status_code=response.status_code,
                temperature=weather_data["main"].get("temp"),
            )

            return TemperatureData(
                temperature=str(round(weather_data["main"]["temp"])), temp_unit="c"
            )

        except requests.exceptions.Timeout:
            Logger.error(f"Timeout while fetching weather data for {city}")
            raise APIError.gateway_timeout(
                message=f"Weather API timed out when fetching data for {city}",
                context={"city": city},
            )

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, "response") else 500
            Logger.error(
                f"HTTP error fetching weather data for {city}",
                status_code=status_code,
                error=str(e),
            )

            if status_code == 404:
                raise APIError.not_found(entity=f"Weather data for {city}")
            elif status_code == 401:
                raise APIError.bad_request(
                    message="Invalid API key for weather service"
                )
            else:
                raise APIError.bad_gateway(message=f"Weather API error: {str(e)}")

        except Exception as e:
            Logger.error(
                f"Error fetching weather data for {city}",
                error_type=type(e).__name__,
                error=str(e),
                exc_info=True,
            )
            raise AppError(
                message=f"Failed to fetch weather data for {city}",
                original_error=e,
                context={"city": city},
            )

    def get_hello_data(self) -> WeatherResponseSchema:
        """
        Get complete data for the /api/hello endpoint.
        """
        # Get current datetime in required format
        now = datetime.datetime.now()
        formatted_datetime = now.strftime("%y%m%d%H%M")

        dhaka_weather = self.get_weather_data()

        # Construct and return the complete response
        return WeatherResponseSchema(
            hostname=socket.gethostname(),
            datetime=formatted_datetime,
            version=__version__,
            weather={"dhaka": dhaka_weather},
        )

    def check_health(self) -> HealthResponseSchema:
        """
        Check the health of the service and its dependencies.
        """
        now = datetime.datetime.now()
        formatted_datetime = now.strftime("%y%m%d%H%M")

        # Default to unhealthy state
        status = "unhealthy"
        weather_service_status = False

        try:
            # Using a simple test query to check API connectivity
            test_params = {"q": "Dhaka", "appid": self.api_key, "units": self.units}
            response = requests.get(
                self.base_url, params=test_params, timeout=self.timeout
            )

            weather_service_status = response.status_code == 200
            status = "healthy" if weather_service_status else "unhealthy"
            response_time = response.elapsed.total_seconds()

        except Exception as e:
            Logger.error("Health check failed for weather API", error=str(e))
            APIError.internal_server_error()

        # Create response according to schema
        health_status = HealthResponseSchema(
            status=status,
            status_code=response.status_code,
            timestamp=formatted_datetime,
            hostname=socket.gethostname(),
            version=__version__,
            external_services={"weather_service": weather_service_status},
            response_time=response_time,
        )

        return health_status
