import os


class Constants:
    """
    Global Constants
    """

    weather_api_key = os.environ.get("WEATHER_API_KEY")
    weather_api_url = "https://api.openweathermap.org/data/2.5/weather"
    weather_api_units = "metric"
    api_timeout = 10
