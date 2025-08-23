import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from .models import Application, ChatMessage


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """When a user connects, join the chat group if authorized."""
        self.application_id = self.scope["url_route"]["kwargs"]["application_id"]
        self.group_name = f"chat_{self.application_id}"

        user = self.scope.get("user", AnonymousUser())
        if await self.user_can_join(self.application_id, user.id):
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        """Route incoming actions to handlers."""
        if not text_data:
            return
        payload = json.loads(text_data)
        user = self.scope["user"]

        action = payload.get("action")
        if not action:
            return

        handlers = {
            "message": self.handle_message,
            "typing": self.handle_typing,
            "read": self.handle_read,
            "edit": self.handle_edit,
            "delete": self.handle_delete,
            "reply": self.handle_reply,
            "pin": self.handle_pin,
        }

        if action in handlers:
            await handlers[action](user, payload)

    # ==========================
    # Action Handlers
    # ==========================
    async def handle_message(self, user, payload):
        text = payload.get("message", "").strip()
        if not text:
            return
        chat_msg = await self.save_message(self.application_id, user.id, text)
        await self.channel_layer.group_send(self.group_name, {"type": "chat.message", **chat_msg})

    async def handle_typing(self, user, payload):
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.typing", "sender": user.username, "typing": bool(payload.get("typing"))},
        )

    async def handle_read(self, user, payload):
        read_ids = payload.get("messages", [])
        if isinstance(read_ids, list):
            await self.mark_messages_read(read_ids)
            await self.channel_layer.group_send(
                self.group_name, {"type": "chat.read", "sender": user.username, "messages": read_ids}
            )

    async def handle_edit(self, user, payload):
        msg_id, new_text = payload.get("id"), payload.get("message", "").strip()
        if msg_id and new_text and await self.edit_message(msg_id, user.id, new_text):
            await self.channel_layer.group_send(
                self.group_name, {"type": "chat.edit", "id": msg_id, "message": new_text, "sender": user.username}
            )

    async def handle_delete(self, user, payload):
        msg_id = payload.get("id")
        if msg_id and await self.delete_message(msg_id, user.id):
            await self.channel_layer.group_send(
                self.group_name, {"type": "chat.delete", "id": msg_id, "sender": user.username}
            )

    async def handle_reply(self, user, payload):
        """Send a reply message referencing another message."""
        reply_to = payload.get("reply_to")  # original message ID
        text = payload.get("message", "").strip()
        if not reply_to or not text:
            return

        chat_msg = await self.save_message(self.application_id, user.id, text, reply_to)
        chat_msg["reply_to"] = reply_to

        await self.channel_layer.group_send(self.group_name, {"type": "chat.reply", **chat_msg})

    async def handle_pin(self, user, payload):
        """Pin or unpin a message (any participant can do this)."""
        msg_id = payload.get("id")
        pin_state = bool(payload.get("pin", True))
        if msg_id and await self.toggle_pin(msg_id, pin_state):
            await self.channel_layer.group_send(
                self.group_name, {"type": "chat.pin", "id": msg_id, "pinned": pin_state, "sender": user.username}
            )

    # ==========================
    # Event Handlers
    # ==========================
    async def chat_message(self, event): await self.send(text_data=json.dumps(event))
    async def chat_typing(self, event): await self.send(text_data=json.dumps(event))
    async def chat_read(self, event): await self.send(text_data=json.dumps(event))
    async def chat_edit(self, event): await self.send(text_data=json.dumps(event))
    async def chat_delete(self, event): await self.send(text_data=json.dumps(event))
    async def chat_reply(self, event): await self.send(text_data=json.dumps(event))
    async def chat_pin(self, event): await self.send(text_data=json.dumps(event))

    # ==========================
    # Database Helpers
    # ==========================
    @database_sync_to_async
    def user_can_join(self, application_id, user_id):
        try:
            app = Application.objects.select_related("job", "applicant", "job__employer").get(id=application_id)
        except Application.DoesNotExist:
            return False
        return user_id in (app.applicant_id, app.job.employer_id)

    @database_sync_to_async
    def save_message(self, application_id, sender_id, message, reply_to=None):
        app = Application.objects.get(id=application_id)
        obj = ChatMessage.objects.create(application=app, sender_id=sender_id, message=message, reply_to_id=reply_to)
        return {"id": obj.id, "sender": obj.sender.username, "message": obj.message, "timestamp": obj.timestamp.isoformat()}

    @database_sync_to_async
    def mark_messages_read(self, message_ids):
        ChatMessage.objects.filter(id__in=message_ids).update(is_read=True)

    @database_sync_to_async
    def edit_message(self, message_id, user_id, new_text):
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.message = new_text
            msg.save(update_fields=["message"])
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def delete_message(self, message_id, user_id):
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.delete()
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def toggle_pin(self, message_id, pin_state):
        try:
            msg = ChatMessage.objects.get(id=message_id)
            msg.is_pinned = pin_state
            msg.save(update_fields=["is_pinned"])
            return True
        except ChatMessage.DoesNotExist:
            return False
