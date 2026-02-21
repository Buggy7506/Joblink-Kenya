import json

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.db import models
from django.utils import timezone

from .models import Application, ChatMessage, HiddenChatMessage, JobApplicantsMessage, PinnedMessage


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
        self.job_group_name = None
        self.user_group_name = None
        
        user = self.scope.get("user") or AnonymousUser()

        if not self.application_id or not user.is_authenticated:
            await self.close()
            return

        self.user_group_name = f"user_{user.id}"

        allowed = await self.user_can_join(self.application_id, user.id)
        if not allowed:
            await self.close()
            return

        job_id = await self.get_application_job_id(self.application_id)
        if job_id:
            self.job_group_name = f"job_applicants_{job_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.channel_layer.group_add(self.user_group_name, self.channel_name)
        if self.job_group_name:
            is_participant = await self.user_is_job_participant(job_id, user.id)
            if is_participant:
                await self.channel_layer.group_add(self.job_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Guard against shutdown race conditions
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name,
            )
        if getattr(self, "user_group_name", None):
            await self.channel_layer.group_discard(
                self.user_group_name,
                self.channel_name,
            )
        if getattr(self, "job_group_name", None):
            await self.channel_layer.group_discard(
                self.job_group_name,
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
            "forward": self.handle_forward,
            "forward_text": self.handle_forward_text,
            "job_message": self.handle_job_message,
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

        await self.mark_messages_read(self.application_id, user.id, message_ids)

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
                "is_edited": True,
            },
        )

    async def handle_delete(self, user, payload):
        msg_id = payload.get("id")
        mode = payload.get("mode") or "everyone"
        if not msg_id:
            return

        if mode == "me":
            hidden = await self.hide_message_for_user(msg_id, user.id, self.application_id)
            if not hidden:
                return

            await self.channel_layer.group_send(
                self.user_group_name,
                {
                    "type": "chat.delete_me",
                    "id": msg_id,
                    "application_id": str(self.application_id),
                    "sender": user.username,
                },
            )
            return

        deleted = await self.delete_message_for_everyone(msg_id, user.id)
        if not deleted:
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.delete",
                "id": msg_id,
                "sender": user.username,
                "message": "This message was deleted",
                "deleted": True,
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

        pin_result = await self.toggle_pin(msg_id, user.id, pin_state)
        if not pin_result["ok"]:
            await self.send(
                text_data=json.dumps(
                    {
                        "type": "chat.pin_denied",
                        "id": msg_id,
                        "reason": pin_result.get("reason", "Permission denied."),
                    }
                )
            )
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "chat.pin",
                "id": msg_id,
                "pinned": pin_state,
                "sender": user.username,
                "pinned_by": pin_result.get("pinned_by"),
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

    async def handle_forward(self, user, payload):
        target_apps = payload.get("target_apps") or []
        message_ids = payload.get("message_ids") or []
        if isinstance(target_apps, str):
            target_apps = [app_id.strip() for app_id in target_apps.split(",") if app_id.strip()]
        if not isinstance(target_apps, list) or not isinstance(message_ids, list):
            return

        forwarded = await self.forward_messages(
            source_application_id=self.application_id,
            sender_id=user.id,
            message_ids=message_ids,
            target_app_ids=target_apps,
        )
        if not forwarded:
            return

        await self.send(
            text_data=json.dumps(
                {
                    "type": "chat.forward_done",
                    "count": forwarded,
                }
            )
        )


    async def handle_forward_text(self, user, payload):
        target_apps = payload.get("target_apps") or []
        message_text = (payload.get("message") or "").strip()
        if isinstance(target_apps, str):
            target_apps = [app_id.strip() for app_id in target_apps.split(",") if app_id.strip()]
        if not message_text or not isinstance(target_apps, list):
            return

        forwarded = await self.forward_text_to_apps(
            sender_id=user.id,
            message_text=message_text,
            target_app_ids=target_apps,
        )
        if not forwarded:
            return

        await self.send(
            text_data=json.dumps(
                {
                    "type": "chat.forward_done",
                    "count": forwarded,
                }
            )
        )

    async def handle_job_message(self, user, payload):
        if not self.job_group_name:
            return

        text = payload.get("message", "").strip()
        if not text:
            return

        allowed = await self.user_is_job_participant_by_application(self.application_id, user.id)
        if not allowed:
            return

        job_id = await self.get_application_job_id(self.application_id)
        if not job_id:
            return

        room_msg = await self.save_job_room_message(job_id, user.id, text)

        await self.channel_layer.group_send(
            self.job_group_name,
            {
                "type": "chat.job_message",
                **room_msg,
            },
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

    async def chat_delete_me(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_reply(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_pin(self, event):
        await self.send(text_data=json.dumps(event))

    async def chat_job_message(self, event):
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
    def get_application_job_id(self, application_id):
        try:
            return Application.objects.only("job_id").get(id=application_id).job_id
        except Application.DoesNotExist:
            return None

    @database_sync_to_async
    def user_is_job_participant(self, job_id, user_id):
        return Application.objects.filter(job_id=job_id).filter(
            models.Q(applicant_id=user_id) | models.Q(job__employer_id=user_id)
        ).exists()

    @database_sync_to_async
    def user_is_job_participant_by_application(self, application_id, user_id):
        try:
            app = Application.objects.select_related("job").only("job_id", "job__employer_id").get(id=application_id)
        except Application.DoesNotExist:
            return False
        if app.job.employer_id == user_id:
            return True            
        return Application.objects.filter(job_id=app.job_id, applicant_id=user_id).exists()

    @database_sync_to_async
    def save_job_room_message(self, job_id, sender_id, message):
        msg = JobApplicantsMessage.objects.create(
            job_id=job_id,
            sender_id=sender_id,
            message=message,
        )
        return {
            "id": msg.id,
            "sender": msg.sender.username,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
        }
    
    @database_sync_to_async
    def save_message(self, application_id, sender_id, message, reply_to=None):
        app = Application.objects.get(id=application_id)
        reply_to_id = None
        if reply_to and str(reply_to).isdigit():
            reply_candidate = ChatMessage.objects.filter(
                id=reply_to,
                application_id=application_id,
            ).first()
            if reply_candidate:
                reply_to_id = reply_candidate.id

        msg = ChatMessage.objects.create(
            application=app,
            sender_id=sender_id,
            message=message,
            reply_to_id=reply_to_id,
        )
        return {
            "id": msg.id,
            "sender": msg.sender.username,
            "message": msg.message,
            "timestamp": msg.timestamp.isoformat(),
        }

    @database_sync_to_async
    def mark_messages_read(self, application_id, user_id, message_ids):
        ids = [msg_id for msg_id in message_ids if str(msg_id).isdigit()]
        if not ids:
            return

        ChatMessage.objects.filter(
            id__in=ids,
            application_id=application_id,
        ).exclude(sender_id=user_id).update(is_read=True)

    @database_sync_to_async
    def edit_message(self, message_id, user_id, new_text):
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.message = new_text
            msg.is_edited = True
            msg.save(update_fields=["message", "is_edited"])
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def delete_message_for_everyone(self, message_id, user_id):
        try:
            msg = ChatMessage.objects.get(id=message_id, sender_id=user_id)
            msg.message = "This message was deleted"
            msg.is_edited = False
            msg.is_pinned = False
            msg.save(update_fields=["message", "is_edited", "is_pinned"])
            PinnedMessage.objects.filter(message=msg).delete()
            return True
        except ChatMessage.DoesNotExist:
            return False


    @database_sync_to_async
    def hide_message_for_user(self, message_id, user_id, application_id):
        try:
            msg = ChatMessage.objects.filter(
                id=message_id,
                application_id=application_id,
                application__job__is_deleted=False,
            ).filter(
                models.Q(application__applicant_id=user_id) | models.Q(application__job__employer_id=user_id)
            ).first()
            if not msg:
                return False

            HiddenChatMessage.objects.get_or_create(message=msg, user_id=user_id)
            return True
        except ChatMessage.DoesNotExist:
            return False

    @database_sync_to_async
    def user_can_access_message(self, message_id, user_id, application_id):
        return ChatMessage.objects.filter(
            id=message_id,
            application_id=application_id,
            application__job__is_deleted=False,
        ).filter(
            models.Q(application__applicant_id=user_id) | models.Q(application__job__employer_id=user_id)
        ).exists()

    @database_sync_to_async
    def toggle_pin(self, message_id, user_id, pin_state):
        try:
            msg = ChatMessage.objects.get(id=message_id)
            if pin_state:
                ChatMessage.objects.filter(application_id=msg.application_id, is_pinned=True).exclude(id=msg.id).update(is_pinned=False)
                PinnedMessage.objects.filter(message__application_id=msg.application_id).exclude(message=msg).delete()
                msg.is_pinned = True
                msg.save(update_fields=["is_pinned"])
                PinnedMessage.objects.update_or_create(
                    message=msg,
                    defaults={"pinned_by_id": user_id},
                )
                return {"ok": True, "pinned_by": self._username_for_id(user_id)}

            pin_entry = PinnedMessage.objects.filter(message=msg).select_related("pinned_by").first()
            if not pin_entry:
                msg.is_pinned = False
                msg.save(update_fields=["is_pinned"])
                return {"ok": True, "pinned_by": None}

            if pin_entry.pinned_by_id != user_id:
                return {
                    "ok": False,
                    "reason": f"Only {pin_entry.pinned_by.username} can unpin this message.",
                    "pinned_by": pin_entry.pinned_by.username,
                }

            msg.is_pinned = False
            msg.save(update_fields=["is_pinned"])
            pin_entry.delete()

            return {"ok": True, "pinned_by": None}
        except ChatMessage.DoesNotExist:
            return {"ok": False, "reason": "Message not found."}

    def _username_for_id(self, user_id):
        app = Application.objects.filter(id=self.application_id).select_related("applicant", "job__employer").first()
        if not app:
            return None
        if app.applicant_id == user_id:
            return app.applicant.username
        if app.job.employer_id == user_id:
            return app.job.employer.username
        return None

    @database_sync_to_async
    def forward_messages(self, source_application_id, sender_id, message_ids, target_app_ids):
        if not message_ids or not target_app_ids:
            return 0

        source_messages = list(
            ChatMessage.objects.filter(
                application_id=source_application_id,
                id__in=message_ids,
            ).order_by("timestamp")
        )
        if not source_messages:
            return 0

        target_ids = [int(app_id) for app_id in target_app_ids if str(app_id).isdigit()]
        if not target_ids:
            return 0

        allowed_targets = set(
            Application.objects.filter(id__in=target_ids).filter(
                models.Q(applicant_id=sender_id) | models.Q(job__employer_id=sender_id)
            ).values_list("id", flat=True)
        )
        if not allowed_targets:
            return 0

        created_count = 0
        for target_id in allowed_targets:
            for original in source_messages:
                ChatMessage.objects.create(
                    application_id=target_id,
                    sender_id=sender_id,
                    message=f"[Forwarded] {original.message}",
                )
                created_count += 1
        return created_count


    @database_sync_to_async
    def forward_text_to_apps(self, sender_id, message_text, target_app_ids):
        target_ids = [int(app_id) for app_id in target_app_ids if str(app_id).isdigit()]
        if not target_ids:
            return 0

        allowed_targets = set(
            Application.objects.filter(id__in=target_ids).filter(
                models.Q(applicant_id=sender_id) | models.Q(job__employer_id=sender_id)
            ).values_list("id", flat=True)
        )
        if not allowed_targets:
            return 0

        created_count = 0
        for target_id in allowed_targets:
            ChatMessage.objects.create(
                application_id=target_id,
                sender_id=sender_id,
                message=f"[Forwarded] {message_text}",
            )
            created_count += 1
        return created_count

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
