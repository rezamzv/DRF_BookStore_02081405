from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ProfileView,
    ChangePasswordView,
    VerifyEmailView,
    ResendVerificationView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
)


urlpatterns = [

    # Authentication
    path('register/', RegisterView.as_view(), name='register'),

    path('login/', LoginView.as_view(), name='login'),

    path('logout/', LogoutView.as_view(), name='logout'),

    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Profile
    path('me/', ProfileView.as_view(), name='profile'),

    # Password
    path(
        'change-password/',
        ChangePasswordView.as_view(),
        name='change_password'
    ),

    path(
        'password-reset/',
        PasswordResetRequestView.as_view(),
        name='password_reset'
    ),

    path(
        'password-reset/confirm/',
        PasswordResetConfirmView.as_view(),
        name='password_reset_confirm'
    ),

    # Email verification
    path(
        'verify-email/',
        VerifyEmailView.as_view(),
        name='verify_email'
    ),

    path(
        'resend-verification/',
        ResendVerificationView.as_view(),
        name='resend_verification'
    ),
]