from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .utils import long as L

urlpatterns = [
    path(L() + "/api/categories/", views.api_job_categories, name="api_categories"),
    path(L() + "/api/locations/", views.api_locations, name="api_locations"),

    # Ping
    path(L() + "/ping/", views.ping, name="ping"),

    # Resume / CV
    path(L() + 'resume/build/', views.alien_resume_builder, name='build_resume'),
    path(L() + 'resume/success/', views.resume_success, name='resume_success'),
    path(L() + 'resume/view/', views.view_resume, name='view_resume'),
    path(L() + 'resume/download/', views.download_resume_pdf, name='download_resume'),

    path(L() + 'upload-cv/', views.upload_cv, name='upload_cv'),
    path(L() + 'delete-cv/', views.delete_cv, name='delete_cv'),
    path(L() + "download-cv/<int:cv_id>/", views.download_cv, name="download_cv"),

    # Auth
    path(L() + 'signup/', views.signup_view, name='signup'),
    path(L() + 'login/', views.login_view, name='login'),
    path(L() + 'login/applicant/', views.login_view, {'role': 'applicant'}, name='login_applicant'),
    path(L() + 'login/employer/', views.login_view, {'role': 'employer'}, name='login_employer'),
    path(L() + 'login/google/', views.google_login, name='google_login'),
    path(L() + 'google/callback/', views.google_callback, name='google_callback'),
    path(L() + 'google/set-password/', views.set_google_password, name='set_google_password'),
    path(L() + 'google/choose-role/', views.google_choose_role, name='google_choose_role'),
    path(L() + "employer/complete-profile/", views.complete_employer_profile, name="complete_employer_profile"),
    path(L() + 'logout/', views.logout_view, name='logout'),
    path(L() + 'logout-success/', views.logout_success, name='logout_success'),
    path(L() + 'change/', views.change_username_password, name='change_username_password'),
    path(L() + 'settings/', views.account_settings, name="account_settings"),
    path(L() + 'delete-account/', views.delete_account, name="delete_account"),
    path(L() + "upload-docs/", views.upload_company_docs, name="upload_company_docs"),

    # Password reset
    path(L() + 'password-reset/', auth_views.PasswordResetView.as_view(
        template_name='password_reset.html'), name='password_reset'),
    path(L() + 'password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='password_reset_done.html'), name='password_reset_done'),
    path(L() + 'reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path(L() + 'reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='password_reset_complete.html'), name='password_reset_complete'),

    # Profile
    path(L() + 'profile/', views.profile_view, name='profile'),
    path(L() + 'edit-profile/', views.edit_profile, name='edit_profile'),
    path(L() + "profile/quick-update/", views.quick_profile_update, name="quick_profile_update"),
    path(L() + 'employer/profile/', views.employer_profile, name='employer_profile'),
    path(L() + 'employer/company-profile/', views.company_profile, name='company_profile'),

    # Jobs
    path(L() + 'available-jobs/', views.available_jobs, name='available_jobs'),
    path(L() + 'jobs/', views.job_list, name='job_list'),
    path(L() + 'jobs/<int:job_id>/', views.job_detail, name='job_detail'),
    path(L() + 'jobs/<int:job_id>/edit/', views.edit_job, name='edit_job'),
    path(L() + 'my-jobs/', views.view_posted_jobs, name='view_posted_jobs'),
    path(L() + 'applicants/', views.view_applicants, name='view_applicants'),
    path(L() + 'post-job/', views.post_job, name='post_job'),
    path(L() + 'jobs/suggestions/', views.job_suggestions, name='job_suggestions'),

    path(L() + 'upgrade-job/<int:job_id>/', views.upgrade_job, name='upgrade_job'),
    path(L() + 'job/<int:job_id>/upgrade/', views.upgrade_job, name='upgrade_job'),

    path(L() + 'payment-success/<int:job_id>/<int:plan_id>/', views.payment_success, name='payment_success'),
    path(L() + 'payment-cancelled/', views.payment_cancelled, name='payment_cancelled'),

    # Applications
    path(L() + 'applied-jobs/', views.view_applications, name='applied_jobs'),
    path(L() + 'apply/<int:job_id>/', views.apply_job, name='apply_job'),
    path(L() + 'apply-success/<int:job_id>/<str:applied>/', views.apply_job_success, name='apply_job_success'),

    path(L() + 'applications/delete/<int:app_id>/', views.delete_application, name='delete_application'),
    path(L() + 'applications/destroy/<int:app_id>/', views.destroy_application, name='destroy_application'),
    path(L() + 'applications/undo/<int:app_id>/', views.undo_delete_application, name='undo_delete_application'),
    path(L() + 'application/process/<int:app_id>/', views.process_application, name='process_application'),

    path(L() + 'recycle-bin/', views.recycle_bin, name='recycle_bin'),

    # Chat & Notifications
    path(L() + 'chat/', views.chat_view, name='employer_chat'),
    path(L() + "chat/job/<int:job_id>/", views.chat_view, name="employer_chat"),
    path(L() + "chat/application/<int:application_id>/", views.chat_view, name="job_chat"),
    path(L() + "chat/message/<int:msg_id>/edit/", views.edit_message, name="edit_message"),
    path(L() + "chat/message/<int:msg_id>/delete/", views.delete_message, name="delete_message"),

    path(L() + "notifications/", views.notifications, name="notifications"),
    path(L() + "notifications/mark-all-read/", views.mark_all_read, name="mark_all_read"),

    # Dashboard
    path(L() + 'dashboard/', views.dashboard, name='dashboard'),
    path(L() + 'admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path(L() + 'admin-profile/', views.admin_profile, name='admin_profile'),
    path(L() + 'admin-only/', views.admin_only_view, name='admin_only'),
    path(L() + 'employer/control-panel/', views.employer_control_panel_view, name='employer_control_panel'),

    # Static
    path(L() + "", views.home, name='home'),
    path(L() + "privacy/", views.privacy_policy, name="privacy_policy"),
    path(L() + "terms/", views.terms_of_service, name="terms_of_service"),
    path(L() + "learn-more/", views.learn_more, name="learn_more"),
    path(L() + "cookies/", views.cookies_policy, name="cookies_policy"),
    path(L() + "resources/", views.resources, name="resources"),

    # Alerts
    path(L() + 'alerts/', views.job_alerts_view, name='job_alerts'),
    path(L() + 'alerts/delete/<int:alert_id>/', views.delete_alert, name='delete_alert'),
    path(L() + 'alerts/delete/success', views.delete_alert_success, name='delete_alert_success'),
]
