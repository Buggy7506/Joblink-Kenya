# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User,
    JobCategory,
    Job,
    Application,
    SkillResource,
    CVUpload,
    Resume,
    Notification,
    JobAlert,
    JobPlan,
    JobPayment,
)
@admin.register(JobPlan)
class JobPlanAdmin(admin.ModelAdmin):
    list_display = ['name', 'price', 'duration_days']

@admin.register(JobPayment)
class JobPaymentAdmin(admin.ModelAdmin):
    list_display = ['employer', 'job', 'amount', 'paid_on', 'is_successful' ]

# Custom User admin
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')
    fieldsets = UserAdmin.fieldsets + (
        ('Role Info', {'fields': ('role',)}),
    )

@admin.register(JobCategory)
class JobCategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'employer', 'location', 'posted_on', 'is_premium', 'premium_expiry')
    list_filter = ('category', 'location')
    search_fields = ('title', 'description', 'employer__username')

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('job', 'applicant', 'applied_on')
    list_filter = ('applied_on',)
    search_fields = ('job__title', 'applicant__username')

@admin.register(SkillResource)
class SkillResourceAdmin(admin.ModelAdmin):
    list_display = ('title', 'link', 'added_on')
    search_fields = ('title',)

@admin.register(CVUpload)
class CVUploadAdmin(admin.ModelAdmin):
    list_display = ('applicant', 'cv', 'uploaded_on')
    search_fields = ('student__username',)

@admin.register(Resume)
class ResumeAdmin(admin.ModelAdmin):
    list_display = ('user', 'email', 'phone', 'created_at')
    search_fields = ('user__username', 'email')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'timestamp')
    search_fields = ('user__username', 'title')

@admin.register(JobAlert)
class JobAlertAdmin(admin.ModelAdmin):
    list_display = ('user', 'job_title', 'location')
    search_fields = ('user__username', 'job_title', 'location')