from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # Homepage
    path('profile/', views.profile_view, name='profile'),
    # User registration
    path('signup/', views.signup_view, name='signup'),
    path('change/', views.change_username_password, name='change_username_password'),
    # Dashboard (role-based content)
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('accounts/login', auth_views.LoginView.as_view, name='login'),
    path('password-reset/', auth_views.PasswordResetView.as_view(
        template_name='password_reset.html'), name='password_reset'),

    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='password_reset_done.html'), name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='password_reset_confirm.html'), name='password_reset_confirm'),

    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='password_reset_complete.html'), name='password_reset_complete'),

    # Employers: Post a job
    path('post-job/', views.post_job, name='post_job'),
    path('admin-only/', views.admin_only_view, name='admin_only'),

    # profile change
    path('edit-profile/', views.edit_profile, name='edit_profile'),
    
    # Students: Upload CV
    path('upload-cv/', views.upload_cv, name='upload_cv'),

    # View available jobs
    path('jobs/', views.job_list, name='job_list'),
    path('my-jobs/', views.view_posted_jobs, name='view_posted_jobs'),
    path('applicants/', views.view_applicants, name='view_applicants'),
    path('employer-profile/', views.employer_profile, name='employer_profile'),

    # Skill-building resources
    path('resources/', views.resources, name='resources'),
    
    # Resume Builder: Create new resume
    path('build/', views.build_resume, name='build_resume'),
    path('build/success', views.resume_success, name='resume_success'),
    path('apply/<int:job_id>/', views.apply_job, name='apply_job'),
    path('apply-success/<int:job_id>/<str:applied>/', views.apply_job_success, name='apply_job_success'),
    # View a specific resume
    path('resume/<int:resume_id>/', views.view_resume, name='view_resume'),
    path('alerts/delete/success', views.delete_alert_success, name='delete_alert_success'),
    path('alerts/delete/<int:alert_id>/', views.delete_alert, name='delete_alert'),

    # Download resume as PDF
    path('resume/<int:resume_id>/download/', views.download_resume_pdf, name='download_resume'),

    # Personalized job suggestions
    path('suggestions/', views.job_suggestions, name='job_suggestions'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('logout-success/', views.logout_success, name='logout_success'),
    # path('apply/<int:job_id>/', views.apply_to_job, name='apply_job'),
    # path('notifications/', views.notifications, name='notifications'),
    path('alerts/', views.job_alerts_view, name='job_alerts' ),
    path('job/<int:job_id>/upgrade/', views.upgrade_job, name='upgrade_job'),
]

