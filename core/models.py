from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
from cloudinary.models import CloudinaryField
from datetime import timedelta

import uuid

class EmployerCompany(models.Model):
    STATUS_PENDING = "pending"
    STATUS_VERIFIED = "verified"
    STATUS_REJECTED = "rejected"

    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending Review"),
        (STATUS_VERIFIED, "Verified"),
        (STATUS_REJECTED, "Rejected"),
    )

    # Tied strictly to user
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="employer_company"
    )

    # Company details
    company_name = models.CharField(max_length=255, blank=True, null=True)
    business_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Must be a business email (no Gmail, Yahoo, etc.)"
    )
    company_website = models.URLField(blank=True, null=True)
    
    # Auto-generated unique registration number
    registration_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        unique=True,
        editable=False,
        help_text="Automatically generated unique company registration number"
    )

    # Verification status
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True
    )
    rejection_reason = models.TextField(blank=True, null=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # -------------------------------------------------------------
    # AUTO VERIFICATION LOGIC
    # -------------------------------------------------------------
    def auto_verify(self):
        """Auto verify based on business email domain + name provided."""
        free_domains = [
            "gmail.com", "yahoo.com", "hotmail.com",
            "outlook.com", "icloud.com"
        ]

        if not self.business_email:
            self.status = self.STATUS_PENDING
            self.rejection_reason = None
            self.reviewed_at = None
            return

        domain = self.business_email.split("@")[-1].lower()

        if domain not in free_domains and self.company_name and self.company_name.strip():
            self.status = self.STATUS_VERIFIED
            self.rejection_reason = None
            self.reviewed_at = timezone.now()
        else:
            self.status = self.STATUS_PENDING
            self.rejection_reason = None
            self.reviewed_at = None

    # -------------------------------------------------------------
    # SAVE OVERRIDE
    # -------------------------------------------------------------
    def save(self, *args, **kwargs):
        # Generate unique registration number if not set
        if not self.registration_number:
            self.registration_number = self.generate_unique_registration_number()

        # Auto-verify status
        self.auto_verify()

        super().save(*args, **kwargs)

    # -------------------------------------------------------------
    # UNIQUE REGISTRATION NUMBER GENERATOR
    # -------------------------------------------------------------
    @staticmethod
    def generate_unique_registration_number():
        """Generate a unique registration number for the employer."""
        while True:
            reg_no = f"EMP{uuid.uuid4().hex[:6].upper()}"  # e.g., EMPA1B2C3
            if not EmployerCompany.objects.filter(registration_number=reg_no).exists():
                return reg_no

    # -------------------------------------------------------------
    # Helpers / Badge Properties
    # -------------------------------------------------------------
    @property
    def is_verified(self):
        return self.status == self.STATUS_VERIFIED

    @property
    def is_pending(self):
        return self.status == self.STATUS_PENDING

    @property
    def is_rejected(self):
        return self.status == self.STATUS_REJECTED

    @property
    def verification_badge(self):
        if self.is_verified:
            return "verified"
        if self.is_pending:
            return "pending"
        return "rejected"

    # -------------------------------------------------------------
    # ✅ NEW: Standardized completeness check
    # -------------------------------------------------------------
    @property
    def is_complete(self):
        """
        Returns True if the company profile is considered complete.
        This is now the single source of truth for redirect checks.
        """
        # Only require fields necessary for critical logic
        return bool(self.company_name and self.business_email)

    def __str__(self):
        return f"{self.company_name or 'Unnamed Company'} [{self.get_status_display()}]"

class CompanyDocument(models.Model):
    DOCUMENT_TYPES = (
        ("incorporation", "Certificate of Incorporation"),
        ("registration", "Business Registration"),
        ("tax", "Tax Certificate"),
        ("other", "Other"),
    )

    company = models.ForeignKey(
        EmployerCompany,
        on_delete=models.CASCADE,
        related_name="documents"
    )

    document_type = models.CharField(
        max_length=30,
        choices=DOCUMENT_TYPES
    )

    file = models.FileField(upload_to="company_docs/")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Keep fields but auto-set them
    is_approved = models.BooleanField(default=False)
    reviewed_at = models.DateTimeField(blank=True, null=True)

    def save(self, *args, **kwargs):
        # Auto approve document
        if not self.is_approved:
            self.is_approved = True
            self.reviewed_at = timezone.now()

        super().save(*args, **kwargs)

        # Auto-verify employer company if not already verified
        company = self.company
        if company.is_pending or company.is_rejected:
            company.status = company.STATUS_VERIFIED
            company.reviewed_at = timezone.now()
            company.rejection_reason = None
            company.save(update_fields=["status", "reviewed_at", "rejection_reason"])

    def __str__(self):
        return f"{self.company.company_name} | {self.document_type}"

# ======================================================
# CUSTOM USER
# ======================================================
class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('applicant', 'Applicant'),
        ('employer', 'Employer'),
        ('admin', 'Admin'),
    )

    # 🔥 OVERRIDE USERNAME
    username = models.CharField(
        max_length=150,
        unique=True,
        null=True,
        blank=True,
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='applicant')
    first_name = models.CharField(max_length=255, default='')
    last_name = models.CharField(max_length=255, default='')

    phone = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        unique=True
    )

    email = models.EmailField(
    unique=True,
    null=True,
    blank=True
    )

    location = models.CharField(max_length=255, blank=True)
    profile_pic = CloudinaryField('image', blank=True, null=True)
    skills = models.CharField(max_length=255, blank=True, null=True)

    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email or self.phone or "User"

    @property
    def profile_picture_url(self):
        if self.profile_pic:
            return self.profile_pic.url
        if hasattr(self, 'profile') and self.profile.profile_pic:
            return self.profile.profile_pic.url
        return "https://res.cloudinary.com/dc6z1giw2/image/upload/v1754578015/jo2wvg1a0wgiava5be20.png"

# ======================================================
# PROFILE
# ======================================================
class Profile(models.Model):

    # ==========================
    # ROLE
    # ==========================
    ROLE_CHOICES = (
        ('applicant', 'Applicant'),
        ('employer', 'Employer'),
    )

    # ==========================
    # DEVICE VERIFICATION
    # ==========================
    VERIFICATION_CHOICES = (
        ('email', 'Email'),
        ('phone', 'Phone'),
    )

    # ==========================
    # RELATION
    # ==========================
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile"
    )

    # ==========================
    # BASIC INFO
    # ==========================
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=255, blank=True)

    profile_pic = CloudinaryField('image', blank=True, null=True)

    bio = models.TextField(blank=True)
    experience = models.TextField(blank=True)
    education = models.TextField(blank=True)
    skills = models.CharField(max_length=255, blank=True, null=True)

    # ==========================
    # ROLE
    # ==========================
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='applicant',
        db_index=True
    )

    # ==========================
    # 🔒 ROLE SECURITY (NEW)
    # ==========================
    role_failed_attempts = models.PositiveIntegerField(default=0)
    role_lock_until = models.DateTimeField(null=True, blank=True)

    # ==========================
    # DEVICE VERIFICATION PREF
    # ==========================
    verification_method = models.CharField(
        max_length=10,
        choices=VERIFICATION_CHOICES,
        default='email'
    )

    # ==========================
    # META
    # ==========================
    created_at = models.DateTimeField(
        default=timezone.now   # ✅ SAFE FOR EXISTING ROWS
    )
    updated_at = models.DateTimeField(auto_now=True)

    # ==========================
    # HELPERS
    # ==========================
    def __str__(self):
        return f"{self.full_name} ({self.role})"

    @property
    def is_employer(self):
        return self.role == "employer"

    @property
    def is_applicant(self):
        return self.role == "applicant"

    def is_role_locked(self):
        """
        Returns True if account is temporarily locked
        due to wrong role attempts.
        """
        return self.role_lock_until and timezone.now() < self.role_lock_until

    def reset_role_lock(self):
        """
        Clears role lock after successful login.
        """
        self.role_failed_attempts = 0
        self.role_lock_until = None
        self.save(update_fields=["role_failed_attempts", "role_lock_until"])

    @property
    def profile_picture_url(self):
        """
        Returns profile picture URL.
        Falls back to user profile pic or default image.
        """
        if self.profile_pic:
            return self.profile_pic.url

        if hasattr(self.user, "profile_pic") and self.user.profile_pic:
            return self.user.profile_pic.url

        return (
            "https://res.cloudinary.com/dc6z1giw2/image/upload/"
            "v1754578015/jo2wvg1a0wgiava5be20.png"
        )


# ======================================================
# DEVICE SECURITY MODELS
# ======================================================

# ---------------------------
# Trusted Device Model
# ---------------------------
class TrustedDevice(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="devices"
    )
    device_fingerprint = models.CharField(max_length=255, unique=True)  # unique fingerprint
    user_agent = models.TextField()
    ip_address = models.CharField(max_length=50)
    location = models.CharField(max_length=255, blank=True, null=True)  # city/country
    verified = models.BooleanField(default=False)  # mark if trusted
    verified_at = models.DateTimeField(blank=True, null=True)  # timestamp when verified
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.device_fingerprint} → {self.user.username}"


# ---------------------------
# Device Verification Model
# ---------------------------
class DeviceVerification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    identifier = models.CharField(max_length=255, db_index=True)
    email = models.EmailField(null=True, blank=True)  # store email if pre-login
    code = models.CharField(max_length=6)  # OTP code
    device_fingerprint = models.CharField(max_length=255)
    user_agent = models.TextField()
    ip_address = models.CharField(max_length=50)
    location = models.CharField(max_length=255, blank=True, null=True)
    is_used = models.BooleanField(default=False)
    verified_via = models.CharField(
        max_length=20,
        choices=[
            ('email', 'Email'),
            ('whatsapp', 'WhatsApp'),
            ('sms', 'SMS')
        ],
        blank=True,
        null=True,
        help_text="Channel used to complete verification"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.user:
            return f"Verification for {self.user.username} ({self.device_fingerprint})"
        elif self.email:
            return f"Verification for {self.email} ({self.device_fingerprint})"
        return f"Verification ({self.device_fingerprint})"

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Device Verification"
        verbose_name_plural = "Device Verifications"


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
    category = models.ForeignKey(
        'JobCategory',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    location = models.CharField(max_length=100)
    employer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="jobs_posted"
    )
    posted_on = models.DateTimeField(auto_now_add=True)
    company = models.CharField(max_length=200, blank=True)
    company_logo = CloudinaryField('image', blank=True, null=True)

    salary = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Enter salary in KES"
    )
    is_premium = models.BooleanField(default=False)
    premium_expiry = models.DateTimeField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)  # Keep this for views
    expiry_date = models.DateTimeField(null=True, blank=True)  # Job expiry date

    def save(self, *args, **kwargs):
        # --- Set default expiry date to 30 days if not provided ---
        if not self.expiry_date:
            self.expiry_date = timezone.now() + timedelta(days=30)

        # --- Auto-set premium based on salary ---
        if self.salary and self.salary > 30000:
            self.is_premium = True
            if not self.premium_expiry:
                self.premium_expiry = timezone.now() + timedelta(days=30)
        else:
            self.is_premium = False
            self.premium_expiry = None

        # --- Auto-disable job if expired ---
        if self.expiry_date <= timezone.now():
            self.is_active = False

        super().save(*args, **kwargs)

    def check_premium_status(self):
        """
        Disable premium if premium_expiry has passed.
        Call this method in views or before displaying premium jobs.
        """
        if self.is_premium and self.premium_expiry and self.premium_expiry < timezone.now():
            self.is_premium = False
            self.save(update_fields=['is_premium'])

    @staticmethod
    def delete_expired_jobs():
        """
        Delete all jobs whose expiry_date has passed.
        Call this in your views if you want to fully purge expired jobs.
        """
        now = timezone.now()
        expired_jobs = Job.objects.filter(expiry_date__lte=now)
        if expired_jobs.exists():
            expired_jobs.delete()

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

    job = models.ForeignKey("Job", on_delete=models.CASCADE, related_name="applications")
    applicant = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'applicant'},
        related_name="applications"
    )

    applied_on = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)

    is_paid = models.BooleanField(default=False)
    mpesa_receipt = models.CharField(max_length=50, blank=True, null=True)

    is_deleted = models.BooleanField(default=False)
    deleted_on = models.DateTimeField(null=True, blank=True)

    is_deleted_for_employer = models.BooleanField(default=False)

    def is_expired(self):
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


class JobApplicantsMessage(models.Model):
    """Shared chat room for a job's employer and all applicants."""

    job = models.ForeignKey("Job", on_delete=models.CASCADE, related_name="applicants_room_messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["timestamp"]

    def __str__(self):
        preview = (self.message[:30] + "...") if len(self.message) > 30 else self.message
        return f"{self.sender.username} @ {self.job_id}: {preview}"


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
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="resumes"
    )
    
    # Full HTML content from the alien_resume_builder (Quill editor)
    content = models.TextField(
        blank=True,
        help_text="Full HTML content created by the user in the resume builder"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # Track changes

    class Meta:
        ordering = ['-updated_at']

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
