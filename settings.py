__all__ = (
    "Settings",
    "app_settings",
)

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    server_private_key_destination = Field(validation_alias="SERVER_PRIVATE_KEY_DESTINATION")
    server_public_key_destination = Field(validation_alias="SERVER_PUBLIC_KEY_DESTINATION")


app_settings = Settings()
