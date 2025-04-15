__all__ = ("User",)

from datetime import datetime
from uuid import uuid4


class User:
    id: uuid4
    login: str
    password: str
    email: str

    created_at: datetime
    updated_at: datetime
