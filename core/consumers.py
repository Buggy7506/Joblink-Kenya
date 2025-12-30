import json

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser

from .models import Application, ChatMessage, PinnedMessage


class ChatConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for application-based chat.
    Designed to shut down cleanly on Render.
    """

    # ==========================
    # Connection lifecycle
    # ==========================
    async def connect(self):
        self.application_id = self.scope["url_route"]["kwargs"].get("application_id")
        self.group_name = f"chat_{self.application_id}"

        user = self.scope.get("user") or AnonymousUser()

        if not self.application_id or not user.is_authenticated:
            await self.close()
            return

        allowed = await self.user_can_join(self.application_id, user.id)
        if not allowed:
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Guard against shutdown race conditions
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name,
            )

    # ==========================
    # Receive messages
    # ==========================
    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return

        try:
            payload = json.loads(text_data)
        except json.JSONDecodeError:
            return

        action = payload.get("action")
        if not action:
            return

        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            return

        handlers = {
            "message": self.handle_message,
            "typing": self.handle_typing,
            "read": self.handle_read,
            "edit": self.handle_edit,
            "delete": self.handle_delete,
            "reply": self.handle_reply,
            "pin": self.handle_pin,
            "get_pins": self.handle_get_pins,
        }

        handler = handlers.get(action)
        if handler:
            await handler(user, payload)

    # ==========================
    # Action handlers
    # ==========================
    async def handle_message(self, user, payload):
        text = payload.get("message", "").strip()
        if not text:
            return

        chat_msg = await self.save_message(
            self.application_id,
            user.id,
            text,
        )

        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.message", **chat_msg},
        )

    async def handle_typing(self, user, payload):
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.typing",
                "sender": user.username,
                "typing": bool(payload.get("typing")),
            },
        )

    async def handle_read(self, user, payload):
        message_ids = payload.get("messages", [])
        if not isinstance(message_ids, list):
            return

        await self.mark_messages_read(message_ids)

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.read",
                "sender": user.username,
                "messages": message_ids,
            },
        )

    async def handle_edit(self, user, payload):
        msg_id = payload.get("id")
        new_text = payload.get("message", "").strip()

        if not msg_id or not new_text:
            return

        updated = await self.edit_message(msg_id, user.id, new_text)
        if not updated:
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.edit",
                "id": msg_id,
                "message": new_text,
                "sender": user.username,
            },
        )

    async def handle_delete(self, user, payload):
        msg_id = payload.get("id")
        if not msg_id:
            return

        deleted = await self.delete_message(msg_id, user.id)
        if not deleted:
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.delete",
                "id": msg_id,
                "sender": user.username,
            },
        )

    async def handle_reply(self, user, payload):
        reply_to = payload.get("reply_to")
        text = payload.get("message", "").strip()

        if not reply_to or not text:
            return

        chat_msg = await self.save_message(
            self.application_id,
            user.id,
            text,
            reply_to=reply_to,
        )

        chat_msg["reply_to"] = reply_to

        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.reply", **chat_msg},
        )

    async def handle_pin(self, user, payload):
        msg_id = payload.get("id")
        pin_state = bool(payload.get("pin", True))

        if not msg_id:
            return

        success = await self.toggle_pin(msg_id, user.id, pin_state)
        if not success:
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.pin",
                "id": msg_id,
                "pinned": pin_state,
                "sender": user.username,
            },
        )

    async def handle_get_pins(self, user, payload):
        pins = await self.get_pinned_messages(self.application_id)
        await self.send(
            text_data=json.dumps(
                {
                    "type": "chat.pins",
                    "pins": pins,
                }
            )
        )

    # ==========================
    # Group event handlers
    # ==========================
    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_typing(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_read(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_edit(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_delete(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_reply(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_pin(self, event):
        await self.send(text_data=json.dumps(event))

    # ==========================
    # Database helpers
    # ==========================
    @database_sync_to_async
    def user_can_join(self, application_id, user_id):
        try:
            app = Application.objects.select_related(
                "job",
                "applicant",
                "job__employer",
            ).get(id=application_id)
        except Application.DoesNotExist:
            return False

        return user_id in (app.applicant_id, app.job.employer_id)

    @database_sync_to_async
    def save_message(self, application_id, sender_id, message, reply_to=None):
        app = Application.objects.get(id=application_id)
        msg = ChatMessage.objects.create(
            application=app,
            sender_id=sender_id,
            message=message,
            reply_to_id=reply_to,
        )
        return {
            "id": msg.id,
            "sender": msg.sender.username,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
        }

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
    def toggle_pin(self, message_id, user_id, pin_state):
        try:
            msg = ChatMessage.objects.get(id=message_id)
            msg.is_pinned = pin_state
            msg.save(update_fields=["is_pinned"])

            if pin_state:
                PinnedMessage.objects.get_or_create(
                    message=msg,
                    pinned_by_id=user_id,
                )
            else:
                PinnedMessage.objects.filter(
                    message=msg,
                    pinned_by_id=user_id,
                ).delete()

            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def get_pinned_messages(self, application_id):
        pins = PinnedMessage.objects.filter(
            message__application_id=application_id,
            message__is_pinned=True,
        ).select_related("message", "pinned_by")

        return [
            {
                "id": p.message.id,
                "message": p.message.message,
                "sender": p.message.sender.username,
                "pinned_by": p.pinned_by.username,
                "timestamp": p.message.timestamp.isoformat(),
            }
            for p in pins
        ]
