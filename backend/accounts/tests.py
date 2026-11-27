
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core import mail
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from .tokens import EmailVerificationToken


User = get_user_model()


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class AccountsAPITests(APITestCase):

    def setUp(self):
        cache.clear()

        self.user = User.objects.create_user(
            email='reza@example.com',
            password='StrongPass123!',
            first_name='Reza',
            last_name='Ahmadi',
            is_email_verified=True
        )

        self.unverified_user = User.objects.create_user(
            email='unverified@example.com',
            password='StrongPass123!',
            first_name='Test',
            last_name='User',
            is_email_verified=False
        )

        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.refresh_url = reverse('token_refresh')
        self.profile_url = reverse('profile')
        self.change_password_url = reverse('change_password')
        self.verify_email_url = reverse('verify_email')
        self.resend_verification_url = reverse('resend_verification')
        self.password_reset_url = reverse('password_reset')
        self.password_reset_confirm_url = reverse('password_reset_confirm')

        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh_token.access_token)

        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

    # =====================================
    # REGISTRATION
    # =====================================

    def test_register_successfully(self):
        self.client.credentials()

        response = self.client.post(
            self.register_url,
            {
                'email': 'newuser@example.com',
                'first_name': 'New',
                'last_name': 'User',
                'password': 'StrongPass123!',
                'password2': 'StrongPass123!',
            }
        )
        print("RESPONSE:", response.data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            User.objects.filter(email='newuser@example.com').exists()
        )
        self.assertEqual(len(mail.outbox), 1)

    def test_register_duplicate_email(self):
        self.client.credentials()

        response = self.client.post(
            self.register_url,
            {
                'email': 'reza@example.com',
                'first_name': 'Another',
                'last_name': 'User',
                'password': 'StrongPass123!',
                'password2': 'StrongPass123!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =====================================
    # LOGIN
    # =====================================

    def test_login_verified_user(self):
        self.client.credentials()

        response = self.client.post(
            self.login_url,
            {
                'email': 'reza@example.com',
                'password': 'StrongPass123!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_unverified_user(self):
        self.client.credentials()

        response = self.client.post(
            self.login_url,
            {
                'email': 'unverified@example.com',
                'password': 'StrongPass123!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_wrong_password(self):
        self.client.credentials()

        response = self.client.post(
            self.login_url,
            {
                'email': 'reza@example.com',
                'password': 'WrongPassword123!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =====================================
    # TOKEN REFRESH
    # =====================================

    def test_refresh_access_token(self):
        self.client.credentials()

        response = self.client.post(
            self.refresh_url,
            {'refresh': str(self.refresh_token)}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    # =====================================
    # LOGOUT
    # =====================================

    def test_logout_successfully(self):
        response = self.client.post(
            self.logout_url,
            {'refresh': str(self.refresh_token)}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_without_refresh_token(self):
        response = self.client.post(
            self.logout_url,
            {}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_with_another_users_token(self):
        another_user = User.objects.create_user(
            email='another@example.com',
            password='StrongPass123!',
            is_email_verified=True
        )

        another_refresh = RefreshToken.for_user(another_user)

        response = self.client.post(
            self.logout_url,
            {'refresh': str(another_refresh)}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =====================================
    # PROFILE
    # =====================================

    def test_get_profile(self):
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)

    def test_update_profile(self):
        response = self.client.patch(
            self.profile_url,
            {'first_name': 'Updated'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')

    def test_profile_requires_authentication(self):
        self.client.credentials()

        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =====================================
    # CHANGE PASSWORD
    # =====================================

    def test_change_password_successfully(self):
        response = self.client.post(self.change_password_url, {
            'old_password': 'StrongPass123!',
            'new_password': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })


        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewStrongPass456!'))

    def test_change_password_wrong_old_password(self):
        response = self.client.post(
            self.change_password_url,
            {
                'old_password': 'WrongPassword123!',
                'new_password': 'NewStrongPass456!',
                'new_password2': 'NewStrongPass456!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =====================================
    # EMAIL VERIFICATION
    # =====================================

    def test_verify_email_successfully(self):
        token = EmailVerificationToken.generate(self.unverified_user)

        self.client.credentials()

        response = self.client.post(
            self.verify_email_url,
            {'token': token}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.unverified_user.refresh_from_db()
        self.assertTrue(self.unverified_user.is_email_verified)

    def test_verify_email_invalid_token(self):
        self.client.credentials()

        response = self.client.post(
            self.verify_email_url,
            {'token': 'invalid-token'}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_email_without_token(self):
        self.client.credentials()

        response = self.client.post(
            self.verify_email_url,
            {}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =====================================
    # RESEND VERIFICATION
    # =====================================

    def test_resend_verification_email(self):
        self.client.credentials()

        response = self.client.post(
            self.resend_verification_url,
            {'email': 'unverified@example.com'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_resend_verification_unknown_email(self):
        self.client.credentials()

        response = self.client.post(
            self.resend_verification_url,
            {'email': 'unknown@example.com'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 0)

    # =====================================
    # PASSWORD RESET REQUEST
    # =====================================

    def test_password_reset_request(self):
        self.client.credentials()

        response = self.client.post(
            self.password_reset_url,
            {'email': 'reza@example.com'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_password_reset_unknown_email(self):
        self.client.credentials()

        response = self.client.post(
            self.password_reset_url,
            {'email': 'unknown@example.com'}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 0)

    # =====================================
    # PASSWORD RESET CONFIRM
    # =====================================

    def test_password_reset_confirm(self):
        self.client.credentials()

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        response = self.client.post(
            self.password_reset_confirm_url,
            {
                'uid': uid,
                'token': token,
                'new_password': 'ResetPass789!',
                'new_password2': 'ResetPass789!',
            }
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('ResetPass789!'))

    def test_password_reset_confirm_invalid_token(self):
        self.client.credentials()

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        response = self.client.post(
            self.password_reset_confirm_url,
            {
                'uid': uid,
                'token': 'invalid-token',
                'new_password': 'ResetPass789!',
                'new_password2': 'ResetPass789!',
            }
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
