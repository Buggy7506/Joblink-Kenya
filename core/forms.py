from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import password_validation
from django.contrib.auth import get_user_model
from django.forms.widgets import ClearableFileInput 
from .models import Job, CVUpload, Resume, JobPlan, CustomUser, Profile, JobCategory
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User


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

    class Meta:
        model = Job
        fields = ['title', 'description', 'category', 'location', 'company', 'salary']  # remove is_premium from form
        help_texts = {
            'title': "Enter the job title.",
            'description': "Provide job details and requirements.",
            'category': "Select or create a job category.",
            'location': "Enter job location.",
            'company': "Enter your company name.",
            'salary': "Enter the salary for this job in KES.",
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
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].required = False

    def save(self, commit=True):
        job = super().save(commit=False)

        # --- Auto-set premium based on salary ---
        if job.salary and job.salary > 30000:
            job.is_premium = True
        else:
            job.is_premium = False
        # ---------------------------------------

        custom_category = self.cleaned_data.get('custom_category')
        if custom_category:
            category, _ = JobCategory.objects.get_or_create(name=custom_category)
            job.category = category

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
        # Exclude admin role from choices
        self.fields['role'].choices = [
            choice for choice in CustomUser.ROLE_CHOICES if choice[0] != 'admin']

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
