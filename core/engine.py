__all__ = ("Engine",)

from datetime import datetime

from websockets.asyncio.server import serve

from core import Authorizer
from settings import app_settings


class Engine:
    host: str = "localhost"
    port: int = 8765
    user_repository: UserRepository = UserRepository()
    chat_repository: ChatRepository = ChatRepository()
    authorizer: Authorizer = Authorizer(user_repository=user_repository, settings=app_settings)

    async def start_server(self):
        async with serve(self._traffic_handler, self.host, self.port) as server:  # noqa
            await server.serve_forever()

    async def _traffic_handler(self, websocket):
        user = self.authorizer.verify_user(websocket.request)

        async for request in websocket:
            receiver = await self.user_repository.extract_receiver(raw_receiver=request["receiver"])

            if not self.chat_repository.find_active_chat_between_users(users_ids=[user.id, receiver.id]):
                await self._perform_key_exchange(request=request)

            message = await self._parse_message(raw_message=request["message"])

            status = await self._send_message(sender=user, receiver=receiver, message=message)
            await self._notify_sender(sender=user, status=status)

    async def _send_message(self, sender, receiver, message):
        composed_message = {
            "sender": {
                "id": sender.id,
                "username": sender.username,
            },
            "message": message,
            "metadata": {
                "sendTime": str(datetime.now()),
            }
        }

        result = await receiver.websocket.send(f"{composed_message}")
        print(result)  # TODO: Remove it
        return "200-delivered"

    async def _notify_sender(self, sender, status):
        delivery_status_message = {
            "sender": {
                "id": "server",
                "username": "ServeR"
            },
            "message": str(status),
            "metadata": {
                "sendTime": str(datetime.now()),
            }
        }

        sender.websocket.send(delivery_status_message)

    async def _parse_message(self, raw_message):
        # TODO: perform special chars escaping
        return str(raw_message)
