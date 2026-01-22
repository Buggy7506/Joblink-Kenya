from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import password_validation
from django.contrib.auth import get_user_model
from django.forms.widgets import ClearableFileInput 
from .models import Job, CVUpload, Resume, JobPlan, CustomUser, Profile, JobCategory, CompanyDocument, EmployerCompany
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from .utils import is_business_email
from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils.text import slugify

ROLE_CHOICES = (
    ('applicant', 'Applicant'),
    ('employer', 'Employer'),
)

class UnifiedAuthForm(forms.Form):
    identifier = forms.EmailField(required=True)
    role = forms.ChoiceField(choices=ROLE_CHOICES, widget=forms.RadioSelect)

    # Employer fields
    company_name = forms.CharField(required=False)
    company_email = forms.EmailField(required=False)
    company_website = forms.URLField(required=False)

    # Step fields
    code = forms.CharField(required=False, max_length=6)
    password = forms.CharField(required=False, widget=forms.PasswordInput)

    # hidden
    action = forms.CharField(widget=forms.HiddenInput, required=False)

    def clean(self):
        cleaned = super().clean()
        role = cleaned.get("role")

        if role == "employer":
            if not cleaned.get("company_name"):
                self.add_error("company_name", "Company name is required.")
            if not cleaned.get("company_email"):
                self.add_error("company_email", "Business email is required.")
        return cleaned

class EmployerCompanyForm(forms.ModelForm):
    # Display-only field for templates
    registration_number_display = forms.CharField(
        label="Registration Number",
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': 'Automatically generated',
            'class': 'form-control',
            'readonly': 'readonly'
        })
    )

    class Meta:
        model = EmployerCompany
        # Non-editable registration number is not included
        fields = ['company_name', 'business_email', 'company_website']
        widgets = {
            'company_name': forms.TextInput(attrs={
                'placeholder': 'Enter your company name',
                'class': 'form-control'
            }),
            'business_email': forms.EmailInput(attrs={
                'placeholder': 'Enter your business email',
                'class': 'form-control'
            }),
            'company_website': forms.URLInput(attrs={
                'placeholder': 'https://yourcompany.com',
                'class': 'form-control'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Prefill the display-only registration number
        if self.instance:
            self.fields['registration_number_display'].initial = (
                self.instance.registration_number
                or self.instance.generate_unique_registration_number()
            )

    def clean_business_email(self):
        email = self.cleaned_data.get('business_email')
        free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"]
        domain = email.split("@")[-1].lower()
        if domain in free_domains:
            raise forms.ValidationError(
                "Please use a business/company email. Free emails (e.g., Gmail, Yahoo, etc.) are not accepted."
            )
        return email

    def save(self, commit=True):
        """
        Ensure registration_number is always set before saving.
        """
        if self.instance and not self.instance.registration_number:
            self.instance.registration_number = self.instance.generate_unique_registration_number()
        return super().save(commit=commit)

class CompanyDocumentForm(forms.ModelForm):
    # Use the document choices from the model
    document_type = forms.ChoiceField(
        choices=CompanyDocument.DOCUMENT_TYPES,
        required=True,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = CompanyDocument
        fields = ["document_type", "file"]
        
class AccountSettingsForm(PasswordChangeForm):
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Username"
        })
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        self.user = user
        self.fields["username"].initial = user.username

        # Apply classes to password fields
        for field in ["old_password", "new_password1", "new_password2"]:
            self.fields[field].widget.attrs.update({
                "class": "form-control",
                "autocomplete": "new-password"
            })

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["username"]
        if commit:
            user.save()
        return user


# 🔹 Utility Mixin for Bootstrap tooltips
class TooltipFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field.help_text:
                field.widget.attrs.update({
                    "data-bs-toggle": "tooltip",
                    "title": field.help_text,
                })
                field.help_text = None  # Prevent default inline rendering


# 🔹 Change Username & Password Form
class ChangeUsernamePasswordForm(TooltipFormMixin, forms.ModelForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter current password'}),
        label="Current Password",
        help_text="Enter your existing password for verification."
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter new password'}),
        label="New Password",
        help_text="Your new password should be strong and secure."
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm new password'}),
        label="Confirm New Password",
        help_text="Re-enter your new password for confirmation."
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'old_password', 'new_password1', 'new_password2']
        help_texts = {
            'username': "Update your username.",
        }
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter username'}),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        if not self.user.check_password(old_password):
            raise forms.ValidationError("Your current password is incorrect.")
        return old_password

    def clean(self):
        cleaned_data = super().clean()
        new1 = cleaned_data.get("new_password1")
        new2 = cleaned_data.get("new_password2")
        if new1 and new2 and new1 != new2:
            raise forms.ValidationError("The new passwords do not match.")
        password_validation.validate_password(new1, self.user)
        return cleaned_data


# 🔹 Job Plan Form
class JobPlanSelectForm(TooltipFormMixin, forms.Form):
    plan = forms.ModelChoiceField(
        queryset=JobPlan.objects.all(),
        empty_label="Select a Premium Plan",
        help_text="Choose your subscription plan."
    )



# 🔹 Profile Edit Form
User = get_user_model()

class EditProfileForm(TooltipFormMixin, forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter new password'}),
        required=False,
        help_text="Leave blank if you don’t want to change."
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm new password'}),
        required=False,
        help_text="Re-enter the new password."
    )

    upload_cv = forms.FileField(
        required=False,
        help_text="Upload your CV in PDF/DOC/DOCX format."
    )

    class Meta:
        model = CustomUser
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'phone', 'location', 'profile_pic', 'skills'
        ]
        help_texts = {
            'username': "Update your username.",
            'email': "Update your email address.",
            'first_name': "Enter your first name.",
            'last_name': "Enter your last name.",
            'phone': "Provide your phone number.",
            'location': "Specify your location.",
            'skills': "List your skills separated by commas.",
        }
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Enter email'}),
            'first_name': forms.TextInput(attrs={'placeholder': 'Enter first name'}),
            'last_name': forms.TextInput(attrs={'placeholder': 'Enter last name'}),
            'phone': forms.TextInput(attrs={'placeholder': 'Enter phone number'}),
            'location': forms.TextInput(attrs={
                'placeholder': 'Enter location',
                'class': 'form-input location-input',
                'data-lat-input': 'latitude',
                'data-lon-input': 'longitude'
            }),
            'skills': forms.Textarea(attrs={
                'placeholder': 'List your skills separated by commas.'
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Pre-fill with the latest CV (if exists)
        from .models import CVUpload
        if self.user:
            latest_cv = CVUpload.objects.filter(applicant=self.user).order_by('-uploaded_on').first()
            if latest_cv:
                self.fields['upload_cv'].initial = latest_cv.cv.name  # use .name for file display

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm = cleaned_data.get('confirm_password')
        if password and password != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)

        # Handle password change
        if self.cleaned_data.get('password'):
            user.set_password(self.cleaned_data['password'])

        if commit:
            user.save()

            # Handle CV upload (replace old with new)
            upload_cv = self.cleaned_data.get('upload_cv')
            if upload_cv:
                from .models import CVUpload
                cv_obj, created = CVUpload.objects.get_or_create(applicant=user)
                cv_obj.cv = upload_cv
                cv_obj.save()

        return user

# 🔹 Job Posting Form
class JobForm(TooltipFormMixin, forms.ModelForm):
    custom_category = forms.CharField(
        max_length=100,
        required=False,
        label="Custom Category",
        widget=forms.TextInput(attrs={'placeholder': 'Enter a custom category'}),
        help_text="You may create your own category if not listed."
    )

    expiry_date = forms.DateTimeField(
        required=False,
        label="Expiry Date",
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        help_text="Optional: Set a custom expiry date for this job. Default is 30 days from posting."
    )

    class Meta:
        model = Job
        fields = ['title', 'description', 'category', 'location', 'company', 'salary', 'expiry_date']
        help_texts = {
            'title': "Enter the job title.",
            'description': "Provide job details and requirements.",
            'category': "Select or create a job category.",
            'location': "Enter job location.",
            'company': "Enter your company name.",
            'salary': "Enter the salary for this job in KES.",
            'expiry_date': "Optional: Set a custom expiry date. Default is 30 days from posting."
        }
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Enter job title'}),
            'description': forms.Textarea(attrs={'placeholder': 'Enter job description'}),
            'location': forms.TextInput(attrs={
                'placeholder': 'Enter job location',
                'class': 'form-input location-input',
                'data-lat-input': 'job-latitude',
                'data-lon-input': 'job-longitude'
            }),
            'company': forms.TextInput(attrs={'placeholder': 'Enter company name'}),
            'salary': forms.NumberInput(attrs={'placeholder': 'Enter salary in KES'}),
            'expiry_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].required = False

    def save(self, commit=True):
        job = super().save(commit=False)

        # --- Auto-set premium based on salary ---
        if job.salary and job.salary > 30000:
            job.is_premium = True
            if not job.premium_expiry:
                job.premium_expiry = timezone.now() + timedelta(days=30)
        else:
            job.is_premium = False
            job.premium_expiry = None
        # ---------------------------------------

        # --- Handle custom category ---
        custom_category = self.cleaned_data.get('custom_category')
        if custom_category:
            category, _ = JobCategory.objects.get_or_create(name=custom_category)
            job.category = category

        # --- Handle optional expiry date ---
        expiry_date = self.cleaned_data.get('expiry_date')
        if expiry_date:
            job.expiry_date = expiry_date
        elif not job.expiry_date:
            # If no expiry date is set, default to 30 days from now
            job.expiry_date = timezone.now() + timedelta(days=30)

        # --- Automatically set is_active based on expiry ---
        if job.expiry_date <= timezone.now():
            job.is_active = False
        else:
            job.is_active = True

        if commit:
            job.save()
        return job
        
# 🔹 CV Upload Form
class CVUploadForm(TooltipFormMixin, forms.ModelForm):
    class Meta:
        model = CVUpload
        fields = ['cv']
        help_texts = {
            'cv': "Upload your CV (PDF or DOCX).",
        }
        widgets = {
            'cv': ClearableFileInput(attrs={'class': 'form-control-file'}),
        }


# 🔹 Resume Form
class ResumeForm(TooltipFormMixin, forms.ModelForm):
    class Meta:
        model = Resume
        exclude = ['user']
        help_texts = {
            'summary': "Write a short summary about yourself.",
            'education': "List your educational background.",
            'experience': "Provide your work experience.",
            'skills': "Mention your key skills.",
        }
        widgets = {
            'summary': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Brief summary'}),
            'education': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Education background'}),
            'experience': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Work experience'}),
            'skills': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Your skills'}),
        }


# 🔹 Custom User Creation Form
class CustomUserCreationForm(TooltipFormMixin, UserCreationForm):
    class Meta:
        model = CustomUser
        fields = (
            "username", "email", "first_name", "last_name",
            "password1", "password2", "phone", "location", "role"
        )
        help_texts = {
            'username': "Choose a username.",
            'email': "Provide your email address.",
            'first_name': "Enter your first name.",
            'last_name': "Enter your last name.",
            'phone': "Enter your phone number.",
            'location': "Enter your location.",
            'role': "Select your role.",
        }
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Enter email'}),
            'first_name': forms.TextInput(attrs={'placeholder': 'Enter first name'}),
            'last_name': forms.TextInput(attrs={'placeholder': 'Enter last name'}),
            'phone': forms.TextInput(attrs={'placeholder': 'Enter phone number'}),
            'location': forms.TextInput(attrs={
                'placeholder': 'Enter location',
                'class': 'form-input location-input',
                'data-lat-input': 'latitude',
                'data-lon-input': 'longitude'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set specific fields as required
        self.fields['username'].required = True
        self.fields['email'].required = False
        self.fields['phone'].required = False
        self.fields['role'].required = True

        # Set non-required fields
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False
        self.fields['location'].required = False

        # Exclude admin role from choices
        self.fields['role'].choices = [
            choice for choice in CustomUser.ROLE_CHOICES if choice[0] != 'admin']

class EmployerSignupForm(CustomUserCreationForm):

    def clean_email(self):
        email = self.cleaned_data.get("email")

        if not is_business_email(email):
            raise forms.ValidationError(
                "Please use a business/admin email address."
            )
        return email

# 🔹 User Email Form
class UserForm(TooltipFormMixin, forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['email']
        help_texts = {
            'email': "Update your email address.",
        }
        widgets = {
            'email': forms.EmailInput(attrs={'placeholder': 'Enter email'}),
        }


# 🔹 Profile Form
class ProfileForm(TooltipFormMixin, forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['full_name', 'phone', 'location', 'profile_pic', 'skills']
        help_texts = {
            'full_name': "Enter your full name.",
            'phone': "Provide your phone number.",
            'location': "Enter your location.",
            'profile_pic': "Upload a profile picture.",
            'skills': "List your skills.",
        }
        widgets = {
            'full_name': forms.TextInput(attrs={'placeholder': 'Enter full name'}),
            'phone': forms.TextInput(attrs={'placeholder': 'Enter phone number'}),
            'location': forms.TextInput(attrs={'placeholder': 'Enter location'}),
            'profile_pic': ClearableFileInput(attrs={'class': 'form-control-file'}),
            'skills': forms.Textarea(attrs={'placeholder': 'Your skills'}),
        }
