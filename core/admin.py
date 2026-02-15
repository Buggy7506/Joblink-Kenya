from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    CustomUser, Profile, JobCategory, Job, Application,
    ChatMessage, PinnedMessage, CVUpload, SkillResource, Notification, JobAlert,
    JobPlan, JobPayment
)

# ======================================================
# CUSTOM USER ADMIN
# ======================================================
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ("username", "email", "role", "phone", "location", "is_staff")
    list_filter = ("role", "is_staff", "is_superuser")
    search_fields = ("username", "email", "first_name", "last_name", "phone")

    fieldsets = UserAdmin.fieldsets + (
        ("Additional Info", {
            "fields": ("role", "phone", "location", "profile_pic", "skills")
        }),
    )


# ======================================================
# PROFILE
# ======================================================
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "full_name", "phone", "location")
    search_fields = ("full_name", "user__username", "phone", "location")


# ======================================================
# JOB CATEGORY
# ======================================================
@admin.register(JobCategory)
class JobCategoryAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    search_fields = ("name",)


# ======================================================
# JOB
# ======================================================
@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ("title", "employer", "category", "location", "is_premium", "posted_on")
    search_fields = ("title", "employer__username", "company", "location")
    list_filter = ("is_premium", "is_active", "category", "location")
    ordering = ("-posted_on",)


# ======================================================
# APPLICATION
# ======================================================
@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ("job", "applicant", "status", "is_paid", "applied_on")
    search_fields = ("job__title", "applicant__username", "mpesa_receipt")
    list_filter = ("status", "is_paid")
    ordering = ("-applied_on",)


# ======================================================
# CHAT MESSAGE
# ======================================================
@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ("sender", "application", "timestamp", "is_read", "is_pinned", "is_edited")
    search_fields = ("sender__username", "message", "application__job__title")
    list_filter = ("is_read", "is_pinned", "is_edited")
    ordering = ("timestamp",)


# ======================================================
# PINNED MESSAGE
# ======================================================
@admin.register(PinnedMessage)
class PinnedMessageAdmin(admin.ModelAdmin):
    list_display = ("message", "pinned_by", "pinned_at")
    search_fields = ("message__message", "pinned_by__username")
    ordering = ("-pinned_at",)


# ======================================================
# CV UPLOAD
# ======================================================
@admin.register(CVUpload)
class CVUploadAdmin(admin.ModelAdmin):
    list_display = ("applicant", "uploaded_on")
    search_fields = ("applicant__username",)


# ======================================================
# RESUME
# ======================================================
class ResumeAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at')  # Only show fields that exist
    search_fields = ('user__username',)    # Optional: search by username
    ordering = ("-created_at",)


# ======================================================
# SKILL RESOURCE
# ======================================================
@admin.register(SkillResource)
class SkillResourceAdmin(admin.ModelAdmin):
    list_display = ("title", "link", "added_on")
    search_fields = ("title", "description")


# ======================================================
# NOTIFICATION
# ======================================================
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("title", "user", "timestamp", "is_read")
    search_fields = ("title", "message", "user__username")
    list_filter = ("is_read",)
    ordering = ("-timestamp",)


# ======================================================
# JOB ALERT
# ======================================================
@admin.register(JobAlert)
class JobAlertAdmin(admin.ModelAdmin):
    list_display = ("user", "job_title", "location")
    search_fields = ("job_title", "user__username", "location")


# ======================================================
# JOB PLAN
# ======================================================
@admin.register(JobPlan)
class JobPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "price", "duration_days", "created_at")
    search_fields = ("name",)
    ordering = ("-created_at",)


# ======================================================
# JOB PAYMENT
# ======================================================
@admin.register(JobPayment)
class JobPaymentAdmin(admin.ModelAdmin):
    list_display = ("employer", "job", "amount", "is_successful", "paid_on")
    search_fields = ("employer__username", "mpesa_receipt")
    list_filter = ("is_successful",)
    ordering = ("-paid_on",)
