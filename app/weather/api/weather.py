from fastapi import APIRouter, Depends

from app.weather import schemas
from app.weather.api.service import WeatherService
from core.error import APIError
from core.logger import get_request_logger


router = APIRouter(prefix="/api", tags=["weather"])


@router.get("/hello", response_model=schemas.WeatherResponseSchema)
def get_weather_info(logger=Depends(get_request_logger)):
    """
    Get weather information
    Returns:
        JSON with hostname, datetime, version and weather data
    """

    logger.info("Processing request for /api/hello endpoint")

    try:
        # Create an instance of WeatherService
        weather_service = WeatherService()
        result = weather_service.get_hello_data()

        logger.info(
            "Successfully fetched weather info",
            hostname=result.hostname,
            datetime=result.datetime,
        )

        return result

    except Exception as e:
        logger.error("Failed to process weather information", exc_info=True)
        raise APIError.internal_server_error(
            message="Failed to process weather information request",
            context={"error": str(e)},
        )


@router.get("/health", response_model=schemas.HealthResponseSchema)
def health_check(logger=Depends(get_request_logger)):
    """
    Health check endpoint that verifies API and dependencies health
    """

    try:
        # Create an instance of WeatherService
        weather_service = WeatherService()
        health_result = weather_service.check_health()

        logger.info("Health check successful, service is healthy")
        return health_result

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", exc_info=True)
        raise APIError.internal_server_error(message="Health check failed")
