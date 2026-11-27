from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import CustomUser
from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)
from .tokens import EmailVerificationToken
from .throttles import (
    LoginThrottle,
    RegisterThrottle,
    PasswordResetThrottle,
)


# ==========================================
# REGISTER
# ==========================================

class RegisterView(APIView):

    permission_classes = [AllowAny]
    throttle_classes = [RegisterThrottle]

    def post(self, request):

        serializer = RegisterSerializer(
            data=request.data
        )

        serializer.is_valid(raise_exception=True)

        user = serializer.save()


        # Generate verification token
        token = EmailVerificationToken.generate(user)

        verification_url = (
            f'{settings.FRONTEND_URL}/verify-email/'
            f'?token={token}'
        )

        # Send verification email
        try:
            send_mail(
                subject='Verify your BookStore account',
                message=(
                    f'Hello {user.first_name},\n\n'
                    f'Please verify your email:\n'
                    f'{verification_url}\n\n'
                    f'This link expires in 24 hours.'
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

            email_sent = True

        except Exception:
            email_sent = False

        return Response(
            {
                'message': (
                    'Registration successful. Please check your email.'
                    if email_sent else
                    'Registration successful, but verification email could not be sent. Please request another email.'
                ),
                'email_sent': email_sent,
                'user': UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED
        )



# ==========================================
# LOGIN
# ==========================================

class LoginView(TokenObtainPairView):

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]


# ==========================================
# LOGOUT
# ==========================================

class LogoutView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)

            # Make sure the token belongs to this user
            if str(token['user_id']) != str(request.user.pk):
                return Response(
                    {'error': 'Invalid refresh token.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token.blacklist()

            return Response(
                {'message': 'Successfully logged out.'},
                status=status.HTTP_200_OK
            )

        except TokenError:
            return Response(
                {'error': 'Invalid or expired token.'},
                status=status.HTTP_400_BAD_REQUEST
            )

# ==========================================
# USER PROFILE
# ==========================================

class ProfileView(RetrieveUpdateAPIView):

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):

        return self.request.user


# ==========================================
# CHANGE PASSWORD
# ==========================================

class ChangePasswordView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )

        serializer.is_valid(raise_exception=True)

        serializer.save()

        return Response(
            {
                'message': 'Password changed successfully.'
            },
            status=status.HTTP_200_OK
        )


# ==========================================
# VERIFY EMAIL
# ==========================================

class VerifyEmailView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):

        token = request.data.get('token')

        if not token:
            return Response(
                {'error': 'Verification token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_id = EmailVerificationToken.verify(token)

        if not user_id:
            return Response(
                {'error': 'Invalid or expired verification link.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = CustomUser.objects.get(pk=user_id)

        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User does not exist.'},
                status=status.HTTP_404_NOT_FOUND
            )

        if user.is_email_verified:
            return Response(
                {'message': 'Email is already verified.'},
                status=status.HTTP_200_OK
            )

        user.is_email_verified = True

        user.save(update_fields=['is_email_verified'])

        return Response(
            {'message': 'Email verified successfully.'},
            status=status.HTTP_200_OK
        )


# ==========================================
# RESEND VERIFICATION EMAIL
# ==========================================

class ResendVerificationView(APIView):

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):

        email = request.data.get('email')

        if not email:
            return Response(
                {'error': 'Email is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = CustomUser.objects.filter(
            email__iexact=email
        ).first()

        # Generic response prevents email enumeration
        if user and not user.is_email_verified:

            token = EmailVerificationToken.generate(user)

            verification_url = (
                f'{settings.FRONTEND_URL}/verify-email/'
                f'?token={token}'
            )

            send_mail(
                'Verify your BookStore account',
                f'Verify your email:\n{verification_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

        return Response(
            {
                'message': (
                    'If the account exists and needs verification, '
                    'a verification email has been sent.'
                )
            },
            status=status.HTTP_200_OK
        )


# ==========================================
# PASSWORD RESET REQUEST
# ==========================================

class PasswordResetRequestView(APIView):

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):

        serializer = PasswordResetRequestSerializer(
            data=request.data
        )

        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        user = CustomUser.objects.filter(
            email__iexact=email,
            is_active=True
        ).first()

        # Don't reveal whether an email exists
        if user:

            uid = urlsafe_base64_encode(
                force_bytes(user.pk)
            )

            token = default_token_generator.make_token(user)

            reset_url = (
                f'{settings.FRONTEND_URL}/reset-password/'
                f'?uid={uid}&token={token}'
            )

            send_mail(
                subject='BookStore password reset',

                message=(
                    f'Hello {user.first_name},\n\n'
                    f'Reset your password using this link:\n'
                    f'{reset_url}'
                ),

                from_email=settings.DEFAULT_FROM_EMAIL,

                recipient_list=[user.email],

                fail_silently=False,
            )

        return Response(
            {
                'message': (
                    'If an account exists with that email, '
                    'a password reset link has been sent.'
                )
            },
            status=status.HTTP_200_OK
        )


# ==========================================
# PASSWORD RESET CONFIRM
# ==========================================

class PasswordResetConfirmView(APIView):

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):

        serializer = PasswordResetConfirmSerializer(
            data=request.data
        )

        serializer.is_valid(raise_exception=True)

        serializer.save()

        return Response(
            {
                'message': 'Password reset successfully.'
            },
            status=status.HTTP_200_OK
        )