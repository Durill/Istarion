__all__ = ("UserRedisRepository",)

from user import IUserInterface


class UserRedisRepository(IUserInterface):
    """
    Just to aquire commiting power!
    """

    def get_user(self, login: str):
        pass

    def check_user_credentials(self, login: str, hashed_password: str):
        pass