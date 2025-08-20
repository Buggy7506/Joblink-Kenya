import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from .models import Application, ChatMessage

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.application_id = self.scope["url_route"]["kwargs"]["application_id"]
        self.group_name = f"chat_{self.application_id}"

        user = self.scope.get("user", AnonymousUser())
        allowed = await self.user_can_join(self.application_id, user.id)

        if allowed:
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        payload = json.loads(text_data)
        user = self.scope["user"]

        # --- Handle new messages ---
        if "message" in payload:
            msg = payload["message"].strip()
            if not msg:
                return
            chat_msg = await self.save_message(self.application_id, user.id, msg)
            event = {
                "type": "chat_message",
                "id": chat_msg["id"],
                "sender": chat_msg["sender"],
                "message": chat_msg["message"],
                "timestamp": chat_msg["timestamp"],
            }
            await self.channel_layer.group_send(self.group_name, event)

        # --- Handle typing indicator ---
        elif "typing" in payload:
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "chat_typing",
                    "sender": user.username,
                    "typing": payload["typing"],
                }
            )

        # --- Handle read receipts ---
        elif "read_messages" in payload:
            read_ids = payload["read_messages"]
            await self.mark_messages_read(read_ids)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "chat_read",
                    "read_messages": read_ids,
                    "sender": user.username,
                }
            )

    # --- Event handlers ---
    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_typing(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_read(self, event):
        await self.send(text_data=json.dumps(event))

    # --- Helpers ---
    @database_sync_to_async
    def user_can_join(self, application_id, user_id):
        try:
            app = Application.objects.select_related(
                "job", "applicant", "job__employer"
            ).get(id=application_id)
        except Application.DoesNotExist:
            return False
        if not app.job.is_premium:
            return False
        return user_id in (app.applicant_id, app.job.employer_id)

    @database_sync_to_async
    def save_message(self, application_id, sender_id, message):
        app = Application.objects.get(id=application_id)
        obj = ChatMessage.objects.create(application=app, sender_id=sender_id, message=message)
        return {
            "id": obj.id,
            "sender": obj.sender.username,
            "message": obj.message,
            "timestamp": obj.timestamp.isoformat(),
        }

    @database_sync_to_async
    def mark_messages_read(self, message_ids):
        ChatMessage.objects.filter(id__in=message_ids).update(is_read=True)
        
