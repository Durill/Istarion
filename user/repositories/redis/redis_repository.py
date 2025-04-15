__all__ = ("UserRedisRepository",)

from user import IUserInterface


class UserRedisRepository(IUserInterface):

    def get_user(self, login: str):
        pass

    def check_user_credentials(self, login: str, hashed_password: str):
        pass