__all__ = ("IUserInterface",)

from abc import ABC, abstractmethod


class IUserInterface(ABC):
    @abstractmethod
    def check_user_credentials(
        self,
        login: str,
        hashed_password: str,
    ):
        raise NotImplementedError

    @abstractmethod
    def get_user(self, login: str):
        raise NotImplementedError
