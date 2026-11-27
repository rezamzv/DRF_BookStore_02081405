from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import CustomUser


# --------------------------------
# USER PROFILE
# --------------------------------

class UserSerializer(serializers.ModelSerializer):

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = CustomUser

        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'phone_number',
            'profile_image',
            'is_email_verified',
            'date_joined',
        ]

        read_only_fields = [
            'id',
            'email',
            'is_email_verified',
            'date_joined',
        ]


# --------------------------------
# REGISTRATION
# --------------------------------

class RegisterSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )

    password2 = serializers.CharField(
        write_only=True
    )

    class Meta:
        model = CustomUser

        fields = [
            'email',
            'first_name',
            'last_name',
            'password',
            'password2',
        ]

    def validate_email(self, value):

        if CustomUser.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                'This email is already registered.'
            )

        return value

    def validate(self, attrs):

        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({
                'password': 'Passwords do not match.'
            })

        return attrs

    def create(self, validated_data):

        validated_data.pop('password2')

        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(
            password=password,
            **validated_data
        )

        return user


# --------------------------------
# LOGIN
# --------------------------------



class LoginSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_email_verified:
            raise serializers.ValidationError(
                'Please verify your email before logging in.'
            )

        data['user'] = UserSerializer(self.user).data

        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['full_name'] = user.full_name

        return token



# --------------------------------
# CHANGE PASSWORD
# --------------------------------

class ChangePasswordSerializer(serializers.Serializer):

    old_password = serializers.CharField(
        write_only=True
    )

    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )

    new_password2 = serializers.CharField(
        write_only=True
    )

    def validate_old_password(self, value):

        user = self.context['request'].user

        if not user.check_password(value):
            raise serializers.ValidationError(
                'Incorrect current password.'
            )

        return value

    def validate(self, attrs):

        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError(
                'New passwords do not match.'
            )

        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError(
                'New password must be different.'
            )

        return attrs

    def save(self, **kwargs):

        user = self.context['request'].user

        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password', 'last_login'])

        return user


# --------------------------------
# PASSWORD RESET REQUEST
# --------------------------------

class PasswordResetRequestSerializer(serializers.Serializer):

    email = serializers.EmailField()


# --------------------------------
# PASSWORD RESET CONFIRMATION
# --------------------------------

class PasswordResetConfirmSerializer(serializers.Serializer):

    uid = serializers.CharField()
    token = serializers.CharField()

    new_password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
    )

    new_password2 = serializers.CharField(
        write_only=True
    )

    def validate(self, attrs):

        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError(
                'Passwords do not match.'
            )

        try:
            user_id = force_str(
                urlsafe_base64_decode(attrs['uid'])
            )

            user = CustomUser.objects.get(pk=user_id)

        except (ValueError, TypeError, CustomUser.DoesNotExist):
            raise serializers.ValidationError(
                'Invalid password reset link.'
            )

        if not default_token_generator.check_token(
            user,
            attrs['token']
        ):
            raise serializers.ValidationError(
                'Invalid or expired password reset link.'
            )

        attrs['user'] = user

        return attrs

    def save(self, **kwargs):

        user = self.validated_data['user']

        user.set_password(
            self.validated_data['new_password']
        )

        user.save()

        return user