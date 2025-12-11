from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
from cloudinary.models import CloudinaryField
from datetime import timedelta


# ======================================================
# CUSTOM USER
# ======================================================
class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('applicant', 'Applicant'),
        ('employer', 'Employer'),
        ('admin', 'Admin'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='applicant')
    first_name = models.CharField(max_length=255, default='')
    last_name = models.CharField(max_length=255, default='')
    phone = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=255, blank=True)
    profile_pic = CloudinaryField('image', blank=True, null=True)
    skills = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.username


# ======================================================
# PROFILE
# ======================================================
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=255, blank=True)
    profile_pic = CloudinaryField('image', blank=True, null=True)
    bio = models.TextField(blank=True)
    experience = models.TextField(blank=True)
    education = models.TextField(blank=True)
    skills = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.full_name


# ======================================================
# JOB CATEGORY
# ======================================================
class JobCategory(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


# ======================================================
# JOB POST
# ======================================================
class Job(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    category = models.ForeignKey(JobCategory, on_delete=models.SET_NULL, null=True, blank=True)
    location = models.CharField(max_length=100)
    employer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="jobs_posted"
    )
    posted_on = models.DateTimeField(auto_now_add=True)
    company = models.CharField(max_length=200, blank=True)
    
    # --- New fields ---
    salary = models.PositiveIntegerField(default=0, help_text="Enter salary in KES")
    is_premium = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    premium_expiry = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        """
        Auto-set premium if salary > 30,000 KES.
        """
        if self.salary > 30000:
            self.is_premium = True
        else:
            self.is_premium = False
        super().save(*args, **kwargs)

    def check_premium_status(self):
        """
        Check if premium has expired and deactivate premium if needed.
        """
        if self.is_premium and self.premium_expiry and self.premium_expiry < timezone.now():
            self.is_premium = False
            self.save()

    def __str__(self):
        return self.title

# ======================================================
# APPLICATIONS
# ======================================================
class Application(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_ACCEPTED, 'Accepted'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    job = models.ForeignKey(
        "Job",
        on_delete=models.CASCADE,
        related_name="applications"
    )

    applicant = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'applicant'},
        related_name="applications"
    )

    applied_on = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)

    # Payment
    is_paid = models.BooleanField(default=False)
    mpesa_receipt = models.CharField(max_length=50, blank=True, null=True)

    # --------------------------
    # Soft delete / Recycle bin
    # --------------------------
    is_deleted = models.BooleanField(default=False)  # Applicant-side soft delete
    deleted_on = models.DateTimeField(null=True, blank=True)

    # Hide application from employer when applicant deletes it
    is_deleted_for_employer = models.BooleanField(default=False)

    def is_expired(self):
        """Auto-expire 7 days after soft delete."""
        if self.deleted_on:
            return timezone.now() > self.deleted_on + timedelta(days=7)
        return False

    class Meta:
        unique_together = ("job", "applicant")

    def __str__(self):
        return f"{self.applicant.username} → {self.job.title}"



# ======================================================
# CHAT MESSAGES
# ======================================================
class ChatMessage(models.Model):
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    is_pinned = models.BooleanField(default=False)
    reply_to = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="replies"
    )
    is_edited = models.BooleanField(default=False)

    class Meta:
        ordering = ["timestamp"]

    def __str__(self):
        preview = (self.message[:30] + "...") if len(self.message) > 30 else self.message
        return f"{self.sender.username}: {preview}"


class PinnedMessage(models.Model):
    message = models.ForeignKey(ChatMessage, on_delete=models.CASCADE, related_name="pinned_entries")
    pinned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    pinned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-pinned_at"]

    def __str__(self):
        return f"Pinned by {self.pinned_by.username}"


# ======================================================
# MESSAGE REACTIONS
# ======================================================
class MessageReaction(models.Model):
    REACTION_CHOICES = (
        ('like', 'Like'),
        ('love', 'Love'),
        ('laugh', 'Laugh'),
        ('sad', 'Sad'),
        ('angry', 'Angry'),
    )

    message = models.ForeignKey(ChatMessage, on_delete=models.CASCADE, related_name="reactions")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    reaction_type = models.CharField(max_length=20, choices=REACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("message", "user", "reaction_type")
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.user.username} reacted {self.reaction_type} to msg {self.message.id}"

# ======================================================
# CV UPLOADS
# ======================================================
class CVUpload(models.Model):
    applicant = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'applicant'}
    )
    cv = CloudinaryField(resource_type='auto')
    uploaded_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.applicant.username} CV"


# ======================================================
# RESUME
# ======================================================
class Resume(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    address = models.CharField(max_length=200)
    summary = models.TextField()
    education = models.TextField()
    experience = models.TextField()
    skills = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s Resume"


# ======================================================
# SKILL RESOURCES
# ======================================================
class SkillResource(models.Model):
    title = models.CharField(max_length=255)
    link = models.URLField()
    description = models.TextField()
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


# ======================================================
# NOTIFICATIONS
# ======================================================
class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.title} → {self.user.username}"


# ======================================================
# JOB ALERTS
# ======================================================
class JobAlert(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=100)
    location = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.user.username} alert for {self.job_title}"


# ======================================================
# JOB PLANS
# ======================================================
class JobPlan(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    duration_days = models.PositiveIntegerField()
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} – Ksh {self.price}"


# ======================================================
# JOB PAYMENTS
# ======================================================
class JobPayment(models.Model):
    employer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'employer'}
    )
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    plan = models.ForeignKey(JobPlan, on_delete=models.SET_NULL, null=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    paid_on = models.DateTimeField(auto_now_add=True)
    is_successful = models.BooleanField(default=False)
    mpesa_receipt = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.employer.username} paid {self.amount}"
