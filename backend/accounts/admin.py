from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser
from .forms import (
    CustomUserCreationForm,
    CustomUserChangeForm,
)


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):

    model = CustomUser

    add_form = CustomUserCreationForm
    form = CustomUserChangeForm

    ordering = ('-date_joined',)

    list_display = (
        'email',
        'first_name',
        'last_name',
        'is_active',
        'is_email_verified',
        'is_staff',
    )

    list_filter = (
        'is_active',
        'is_email_verified',
        'is_staff',
        'is_superuser',
    )

    search_fields = (
        'email',
        'first_name',
        'last_name',
    )

    readonly_fields = (
        'date_joined',
        'last_login',
        'updated_at',
    )

    fieldsets = (
        ('Account', {
            'fields': (
                'email',
                'password',
            )
        }),

        ('Personal Information', {
            'fields': (
                'first_name',
                'last_name',
                'phone_number',
                'profile_image',
            )
        }),

        ('Permissions', {
            'fields': (
                'is_active',
                'is_email_verified',
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions',
            )
        }),

        ('Dates', {
            'fields': (
                'date_joined',
                'last_login',
                'updated_at',
            )
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),

            'fields': (
                'email',
                'first_name',
                'last_name',
                'password1',
                'password2',
                'is_staff',
                'is_superuser',
            ),
        }),
    )