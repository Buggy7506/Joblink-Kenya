from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User  # For EditProfileForm and UserRegisterForm
from .models import Job, CVUpload, Resume, JobPlan, CustomUser, Profile, JobCategory
from django.contrib.auth import get_user_model
from django.forms.widgets import ClearableFileInput 
from django.contrib.auth import password_validation

class ChangeUsernamePasswordForm(forms.ModelForm):
    old_password = forms.CharField(widget=forms.PasswordInput(), label="Current Password")
    new_password1 = forms.CharField(widget=forms.PasswordInput(), label="New Password")
    new_password2 = forms.CharField(widget=forms.PasswordInput(), label="Confirm New Password")

    class Meta:
        model = CustomUser
        fields = ['username', 'old_password', 'new_password1', 'new_password2']

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


class JobPlanSelectForm(forms.Form):
    plan = forms.ModelChoiceField(queryset=JobPlan.objects.all(), empty_label="Select a Premium Plan")

# Extended User Registration Form with Role (for Custom User model)
class RegisterForm(UserCreationForm):
    class Meta:
        model = CustomUser  # Replace with your custom User model if different
        fields = ['username', 'email', 'password1', 'password2', 'role' ]

# Basic user registration form (alternative without role)
class UserRegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']

# Edit Profile Form

User = get_user_model()

class EditProfileForm(forms.ModelForm):
    phone = forms.CharField(max_length=20, required=False)
    location = forms.CharField(max_length=100, required=False)
    profile_pic = forms.ImageField(required=False)
    skills = forms.CharField(max_length=255, required=False)
    password = forms.CharField(widget=forms.PasswordInput(), required=False)
    confirm_password = forms.CharField(widget=forms.PasswordInput(), required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'location', 'phone', 'skills'] 

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(EditProfileForm, self).__init__(*args, **kwargs)

        if self.user:
            profile = getattr(self.user, 'profile', None)
            if profile:
                self.fields['phone'].initial = profile.phone
                self.fields['location'].initial = profile.location
                self.fields['profile_pic'].initial = profile.profile_pic
                self.fields['skills'].initial = profile.skills

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm = cleaned_data.get('confirm_password')
        if password and password != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get('password'):
            user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()

            profile, _ = Profile.objects.get_or_create(user=user)
            profile.phone = self.cleaned_data['phone']
            profile.location = self.cleaned_data['location']
            profile.skills = self.cleaned_data.get('skills', '') 

            if self.cleaned_data.get('profile_pic'):
                profile.profile_pic = self.cleaned_data['profile_pic']

            profile.save()

        return user
        
# Job Posting Form (excluding employer to auto-assign it in views)
class JobForm(forms.ModelForm):
    custom_category = forms.CharField(
        max_length=100, 
        required=False, 
        label="Custom Category", 
        widget=forms.TextInput(attrs={'placeholder': 'Enter a custom category'}))

    class Meta:
        model = Job
        fields = ['title', 'description', 'category', 'location', 'company', 'is_premium']

    def __init__(self, *args, **kwargs):
        super(JobForm, self).__init__(*args, **kwargs)
        self.fields['category'].required = False

    def save(self, commit=True):
        job = super().save(commit=False)
        custom_category = self.cleaned_data.get('custom_category')
        if custom_category:
            category, _ = JobCategory.objects.get_or_create(name=custom_category)
            job.category = category
        if commit:
            job.save()
        return job
        # OR: use fields = '__all__' and exclude = ['employer'] if more fields needed

# CV Upload Form (for uploading PDF/Docx)
class CVUploadForm(forms.ModelForm):
    class Meta:
        model = CVUpload
        fields = ['cv']

# Resume Builder Form
class ResumeForm(forms.ModelForm):
    class Meta:
        model = Resume
        exclude = ['user']
        widgets = {
            'summary': forms.Textarea(attrs={'rows': 2}),
            'education': forms.Textarea(attrs={'rows': 2}),
            'experience': forms.Textarea(attrs={'rows': 2}),
            'skills': forms.Textarea(attrs={'rows': 2}),
        }

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ("username", "email", "first_name", "last_name", "password1", "password2", "phone", "location", 'role')      
    def __init__(self, *args, **kwargs):
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)
        self.fields['role'].choices = [choice for choice in CustomUser.ROLE_CHOICES if choice[0] != 'admin']


class UserForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['email']


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['full_name', 'phone', 'location', 'profile_pic', 'skills']
        widgets = {
            'profile_pic': ClearableFileInput(attrs={'class': 'form-control-file'}),
        }
