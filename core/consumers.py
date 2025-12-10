import json
from typing import Optional, List, Dict
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.db.models import Count
from .models import Application, ChatMessage, PinnedMessage, MessageReaction


class ChatConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time chat with reactions, pins, and read receipts."""

    async def connect(self):
        self.application_id: int = self.scope["url_route"]["kwargs"]["application_id"]
        self.group_name: str = f"chat_{self.application_id}"
        self.user = self.scope.get("user", AnonymousUser())

        if await self.user_can_join(self.application_id, self.user.id):
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, code: int):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data: Optional[str] = None, bytes_data=None):
        if not text_data:
            return

        payload = json.loads(text_data)
        action = payload.get("action")
        if not action:
            return

        handlers: Dict[str, callable] = {
            "message": self.handle_message,
            "typing": self.handle_typing,
            "read": self.handle_read,
            "edit": self.handle_edit,
            "delete": self.handle_delete,
            "reply": self.handle_reply,
            "pin": self.handle_pin,
            "get_pins": self.handle_get_pins,
            "react": self.handle_react,
        }

        handler = handlers.get(action)
        if handler:
            await handler(payload)

    # ==========================
    # Action Handlers
    # ==========================
    async def handle_message(self, payload):
        text = payload.get("message", "").strip()
        if not text:
            return
        chat_msg = await self.save_message(self.application_id, self.user.id, text)
        await self.broadcast("chat.message", chat_msg)

    async def handle_typing(self, payload):
        await self.broadcast(
            "chat.typing",
            {"sender": self.user.username, "typing": bool(payload.get("typing"))},
            exclude_self=True,
        )

    async def handle_read(self, payload):
        read_ids: List[int] = payload.get("messages", [])
        if isinstance(read_ids, list):
            await self.mark_messages_read(self.user.id, read_ids)
            await self.broadcast(
                "chat.read", {"sender": self.user.username, "messages": read_ids}
            )

    async def handle_edit(self, payload):
        msg_id = payload.get("id")
        new_text = payload.get("message", "").strip()
        if msg_id and new_text and await self.edit_message(msg_id, self.user.id, new_text):
            await self.broadcast("chat.edit", {"id": msg_id, "message": new_text, "sender": self.user.username})

    async def handle_delete(self, payload):
        msg_id = payload.get("id")
        if msg_id and await self.delete_message(msg_id, self.user.id):
            await self.broadcast("chat.delete", {"id": msg_id, "sender": self.user.username})

    async def handle_reply(self, payload):
        reply_to = payload.get("reply_to")
        text = payload.get("message", "").strip()
        if not reply_to or not text:
            return
        chat_msg = await self.save_message(self.application_id, self.user.id, text, reply_to)
        chat_msg["reply_to"] = reply_to
        await self.broadcast("chat.reply", chat_msg)

    async def handle_pin(self, payload):
        msg_id = payload.get("id")
        pin_state = bool(payload.get("pin", True))
        if msg_id and await self.toggle_pin(msg_id, self.user.id, pin_state):
            await self.broadcast("chat.pin", {"id": msg_id, "pinned": pin_state, "sender": self.user.username})

    async def handle_get_pins(self, payload):
        pins = await self.get_pinned_messages(self.application_id)
        await self.send_json({"type": "chat.pins", "pins": pins})

    async def handle_react(self, payload):
        msg_id = payload.get("id")
        reaction = payload.get("reaction")
        if not msg_id or not reaction:
            return
        updated_reactions = await self.toggle_reaction(msg_id, self.user.id, reaction)
        await self.broadcast("chat.react", {"id": msg_id, "reactions": updated_reactions})

    # ==========================
    # Broadcast Helper
    # ==========================
    async def broadcast(self, event_type: str, data: dict, exclude_self: bool = False):
        """Broadcast an event to the group, optionally excluding sender."""
        message = {"type": event_type, **data}
        if exclude_self:
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "send_to_others", "message": message, "exclude": self.channel_name},
            )
        else:
            await self.channel_layer.group_send(self.group_name, message)

    async def send_to_others(self, event):
        if event.get("exclude") != self.channel_name:
            await self.send_json(event["message"])

    # ==========================
    # Database Helpers
    # ==========================
    @database_sync_to_async
    def user_can_join(self, application_id: int, user_id: int) -> bool:
        try:
            app = Application.objects.select_related("job", "applicant", "job__employer").get(id=application_id)
        except Application.DoesNotExist:
            return False
        return user_id in (app.applicant_id, app.job.employer_id)

    @database_sync_to_async
    def save_message(self, application_id: int, sender_id: int, message: str, reply_to: Optional[int] = None) -> dict:
        app = Application.objects.get(id=application_id)
        obj = ChatMessage.objects.create(application=app, sender_id=sender_id, message=message, reply_to_id=reply_to)
        return self.serialize_message(obj)

    @database_sync_to_async
    def mark_messages_read(self, user_id: int, message_ids: List[int]):
        ChatMessage.objects.filter(id__in=message_ids).update(is_read=True)

    @database_sync_to_async
    def edit_message(self, message_id: int, user_id: int, new_text: str) -> bool:
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.message = new_text
            msg.is_edited = True
            msg.save(update_fields=["message", "is_edited"])
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def delete_message(self, message_id: int, user_id: int) -> bool:
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.delete()
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def toggle_pin(self, message_id: int, user_id: int, pin_state: bool) -> bool:
        try:
            msg = ChatMessage.objects.get(id=message_id)
            msg.is_pinned = pin_state
            msg.save(update_fields=["is_pinned"])
            if pin_state:
                PinnedMessage.objects.get_or_create(message=msg, pinned_by_id=user_id)
            else:
                PinnedMessage.objects.filter(message=msg, pinned_by_id=user_id).delete()
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def get_pinned_messages(self, application_id: int) -> List[dict]:
        qs = PinnedMessage.objects.filter(message__application_id=application_id, message__is_pinned=True).select_related("message", "pinned_by")
        return [self.serialize_message(p.message, p.pinned_by.username) for p in qs]

    @database_sync_to_async
    def toggle_reaction(self, message_id: int, user_id: int, reaction: str) -> dict:
        msg = ChatMessage.objects.get(id=message_id)
        reaction_obj, created = MessageReaction.objects.get_or_create(message=msg, user_id=user_id, reaction=reaction)
        if not created:
            reaction_obj.delete()
        reactions = MessageReaction.objects.filter(message=msg).values("reaction").annotate(count=Count("id"))
        return {r["reaction"]: r["count"] for r in reactions}

    # ==========================
    # Serializer
    # ==========================
    def serialize_message(self, msg: ChatMessage, pinned_by: Optional[str] = None) -> dict:
        return {
            "id": msg.id,
            "sender": msg.sender.username,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
            "reply_to": msg.reply_to_id,
            "is_pinned": msg.is_pinned,
            "pinned_by": pinned_by,
        }
