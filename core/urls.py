from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path("Sign-In-OR-Sign-Up/", views.unified_auth_view, name="unified_auth"),
    
    path("api/categories/", views.api_job_categories, name="api_categories"),
    path("api/locations/", views.api_locations, name="api_locations"),
    # -------------------------
    # Ping URL
    # -------------------------
    path("ping/", views.ping, name="ping"),
    # -------------------------
    # Resume / CV URLs
    # -------------------------
    path('resume/build/', views.alien_resume_builder, name='build_resume'),
    path('resume/success/', views.resume_success, name='resume_success'),
    path('resume/view/', views.view_resume, name='view_resume'),
    path('resume/download/', views.download_resume_pdf, name='download_resume'),

    # Upload / Delete CV (legacy)
    path('upload-cv/', views.upload_cv, name='upload_cv'),
    path('delete-cv/', views.delete_cv, name='delete_cv'),
    path("download-cv/<int:cv_id>/", views.download_cv, name="download_cv"),

    # -------------------------
    # Authentication / Account
    # -------------------------
    #path('signup/', views.signup_view, name='signup'),
    #path('login/', views.login_view, name='login'),
    path('auth/google/', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),
    path('auth/set-password/', views.set_google_password, name='set_google_password'),
    path('auth/choose-role/', views.google_choose_role, name='google_choose_role'),
    path("auth/apple/", views.apple_login, name="apple_login"),
    path('auth/callback/', views.apple_callback, name='apple_callback'),
    path("auth/microsoft/", views.microsoft_login, name="microsoft_login"),
    path('auth/callback/', views.microsoft_callback, name='microsoft_callback'),
    path("employer/complete-profile/", views.complete_employer_profile, name="complete_employer_profile"),
    path('logout/', views.logout_view, name='logout'),
    path('logout-success/', views.logout_success, name='logout_success'),
    path('change/', views.change_username_password, name='change_username_password'),
    path('settings/', views.account_settings, name="account_settings"),
    path('delete-account/', views.delete_account, name="delete_account"),
    path("upload-docs/", views.upload_company_docs, name="upload_company_docs"),

    # Password reset
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
        
    #path('password-reset/', auth_views.PasswordResetView.as_view(
    #    template_name='password_reset.html'), name='password_reset'),
    #path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
    #    template_name='password_reset_done.html'), name='password_reset_done'),
    #path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
    #    template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    #path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
    #   template_name='password_reset_complete.html'), name='password_reset_complete'),

    # -------------------------
    # Profile URLs
    # -------------------------
    path('profile/', views.profile_view, name='profile'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
    path("profile/quick-update/", views.quick_profile_update, name="quick_profile_update"),
    path('employer/profile/', views.employer_profile, name='employer_profile'),
    path('employer/company-profile/', views.company_profile, name='company_profile'),

    # -------------------------
    # Job / Applications
    # -------------------------
    path('available-jobs/', views.available_jobs, name='available_jobs'),
    path('jobs/', views.job_list, name='job_list'),
    path('jobs/<int:job_id>/', views.job_detail, name='job_detail'),
    path('jobs/<int:job_id>/edit/', views.edit_job, name='edit_job'),
    path('my-jobs/', views.view_posted_jobs, name='view_posted_jobs'),
    path('applicants/', views.view_applicants, name='view_applicants'),
    path('post-job/', views.post_job, name='post_job'),
    path('jobs/suggestions/', views.job_suggestions, name='job_suggestions'),

    path('job/<int:job_id>/upgrade/', views.upgrade_job, name='upgrade_job'),
    path('job/<int:job_id>/delete/', views.confirm_delete, name='confirm_delete'),

    path('payment-success/<int:job_id>/<int:plan_id>/', views.payment_success, name='payment_success'),
    path('payment-cancelled/', views.payment_cancelled, name='payment_cancelled'),

    # Applications
    path('applied-jobs/', views.view_applications, name='applied_jobs'),
    path('apply/<int:job_id>/', views.apply_job, name='apply_job'),
    path('apply-success/<int:job_id>/<str:applied>/', views.apply_job_success, name='apply_job_success'),

    path('applications/delete/<int:app_id>/', views.delete_application, name='delete_application'),
    path('applications/destroy/<int:app_id>/', views.destroy_application, name='destroy_application'),
    path('applications/undo/<int:app_id>/', views.undo_delete_application, name='undo_delete_application'),
    path('application/process/<int:app_id>/', views.process_application, name='process_application'),

    path('recycle-bin/', views.recycle_bin, name='recycle_bin'),

    # -------------------------
    # Chat & Notifications
    # -------------------------
    path('chat/', views.chat_view, name='employer_chat'),
    path("chat/job/<int:job_id>/", views.chat_view, name="employer_chat"),
    path("chat/application/<int:application_id>/", views.chat_view, name="job_chat"),
    path("chat/message/<int:msg_id>/edit/", views.edit_message, name="edit_message"),
    path("chat/message/<int:msg_id>/delete/", views.delete_message, name="delete_message"),

    path("notifications/", views.notifications, name="notifications"),
    path("notifications/mark-all-read/", views.mark_all_read, name="mark_all_read"),

    # -------------------------
    # Admin / Dashboard
    # -------------------------
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-profile/', views.admin_profile, name='admin_profile'),
    path('admin-only/', views.admin_only_view, name='admin_only'),
    path('dashboard/', views.employer_control_panel_view, name='employer_control_panel'),

    # -------------------------
    # Miscellaneous / Static
    # -------------------------
    path('', views.home, name='home'),
    path("privacy/", views.privacy_policy, name="privacy_policy"),
    path("terms/", views.terms_of_service, name="terms_of_service"),
    path("learn-more/", views.learn_more, name="learn_more"),
    path("cookies/", views.cookies_policy, name="cookies_policy"),
    path("resources/", views.resources, name="resources"),

    # Alerts
    path('alerts/', views.job_alerts_view, name='job_alerts'),
    path('alerts/delete/<int:alert_id>/', views.delete_alert, name='delete_alert'),
    path('alerts/delete/success', views.delete_alert_success, name='delete_alert_success'),
]  
