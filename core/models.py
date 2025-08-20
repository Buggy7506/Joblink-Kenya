# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.contrib.auth.models import User
from django.conf import settings
from cloudinary.models import CloudinaryField

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

# Custom User model with roles
class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('applicant', 'Applicant'),
        ('employer', 'Employer'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    first_name = models.CharField(max_length=255, default='')
    last_name = models.CharField(max_length=255, default='')
    phone = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=255, blank=True)
    profile_pic = CloudinaryField('image', blank=True, null=True)
    skills = models.CharField(max_length=255, blank=True, null=True)
    def __str__(self):
        return self.username
        
# Job Categories (e.g., IT, Accounting, etc.)
class JobCategory(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

# Job Postings
from django.db import models
from django.conf import settings
from django.utils import timezone

# Job Categories (assumed to exist)
class JobCategory(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Job(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    category = models.ForeignKey(JobCategory, on_delete=models.SET_NULL, blank=True, null=True)
    location = models.CharField(max_length=100)
    employer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="jobs_posted")
    posted_on = models.DateTimeField(auto_now_add=True)
    is_premium = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    premium_expiry = models.DateTimeField(null=True, blank=True)
    company = models.CharField(max_length=200, blank=True)

    def check_premium_status(self):
        """Automatically disable premium if expired."""
        if self.is_premium and self.premium_expiry and self.premium_expiry < timezone.now():
            self.is_premium = False
            self.save()

    def mark_as_inactive_if_needed(self):
        """Optional: deactivate job if past expiry or not active."""
        if not self.is_active:
            self.is_active = False
            self.save()

    def __str__(self):
        return self.title


class Application(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_ACCEPTED, 'Accepted'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name="applications")
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

    class Meta:
        unique_together = ("job", "applicant")  # One application per job/applicant

    def unread_messages_for_user(self, user):
        """Return queryset of unread messages for this user."""
        return self.messages.filter(is_read=False).exclude(sender=user)

    def __str__(self):
        return f"{self.applicant.username} → {self.job.title}"


class ChatMessage(models.Model):
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)  # Tracks if recipient has read the message

    class Meta:
        ordering = ["timestamp"]

    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.save()

    def __str__(self):
        return f"{self.sender.username} @ {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"



# CV Uploads
class CVUpload(models.Model):
    applicant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, limit_choices_to={'role': 'applicant'})
    cv = CloudinaryField(resource_type='auto')  # supports PDF, DOCX, JPG etc
    uploaded_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.applicant.username} CV"

# Resume Builder Info
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

# Skill Resources
class SkillResource(models.Model):
    title = models.CharField(max_length=255)
    link = models.URLField()
    description = models.TextField()
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

# Notifications
class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} → {self.user.username}"

# Job Alerts
class JobAlert(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=100)
    location = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.user.username} alert for {self.job_title} in {self.location}"
        

class JobPlan(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    duration_days = models.PositiveIntegerField()
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} – Ksh {self.price}"

class JobPayment(models.Model):
    employer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, limit_choices_to={'role': 'employer'})
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    plan = models.ForeignKey(JobPlan, on_delete=models.SET_NULL, null=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    paid_on = models.DateTimeField(auto_now_add=True)
    is_successful = models.BooleanField(default=False)
    mpesa_receipt = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.employer.username} paid {self.amount} for {self.job.title}"

