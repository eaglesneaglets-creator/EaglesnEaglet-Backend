"""
User Models

Custom user model with comprehensive security features and role-based access.
"""

import uuid
import secrets
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator
from core.mixins.timestamp import TimestampMixin
from core.validators import validate_phone_number


class UserManager(BaseUserManager):
    """
    Custom user manager for email-based authentication.
    """

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_email_verified', True)
        extra_fields.setdefault('role', User.Role.ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, TimestampMixin):
    """
    Custom User model with enhanced security features.
    """

    class Role(models.TextChoices):
        EAGLE = 'eagle', 'Eagle (Mentor)'
        EAGLET = 'eaglet', 'Eaglet (Mentee)'
        ADMIN = 'admin', 'Admin'

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        INACTIVE = 'inactive', 'Inactive'
        SUSPENDED = 'suspended', 'Suspended'
        PENDING_VERIFICATION = 'pending', 'Pending Verification'

    # Primary identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Authentication fields
    email = models.EmailField(
        unique=True,
        db_index=True,
        error_messages={'unique': 'A user with this email already exists.'}
    )
    is_email_verified = models.BooleanField(default=False)

    # Profile fields
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        validators=[validate_phone_number],
        help_text='Nigerian phone number'
    )
    is_phone_verified = models.BooleanField(default=False)

    # Role and permissions
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.EAGLET
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING_VERIFICATION
    )

    # Profile image
    avatar = models.ImageField(
        upload_to='avatars/%Y/%m/',
        blank=True,
        null=True
    )

    # Bio and additional info
    bio = models.TextField(max_length=500, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)

    # Django admin fields
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Security fields
    failed_login_attempts = models.PositiveIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    lockout_until = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)

    # Email verification
    email_verification_token = models.CharField(max_length=100, blank=True)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)

    # Password reset
    password_reset_token = models.CharField(max_length=100, blank=True)
    password_reset_sent_at = models.DateTimeField(null=True, blank=True)

    # Terms acceptance
    terms_accepted_at = models.DateTimeField(null=True, blank=True)
    privacy_accepted_at = models.DateTimeField(null=True, blank=True)

    # Soft delete
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['role']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f'{self.full_name} ({self.email})'

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'.strip()

    @property
    def is_eagle(self):
        return self.role == self.Role.EAGLE

    @property
    def is_eaglet(self):
        return self.role == self.Role.EAGLET

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN or self.is_superuser

    @property
    def is_account_locked(self):
        if self.lockout_until and self.lockout_until > timezone.now():
            return True
        return False

    def increment_failed_login(self):
        """Increment failed login counter and lock if necessary."""
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()

        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.lockout_until = timezone.now() + timezone.timedelta(minutes=30)

        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'lockout_until'])

    def reset_failed_login(self):
        """Reset failed login counter on successful login."""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.lockout_until = None
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'lockout_until'])

    def generate_email_verification_token(self):
        """Generate a secure email verification token."""
        self.email_verification_token = secrets.token_urlsafe(32)
        self.email_verification_sent_at = timezone.now()
        self.save(update_fields=['email_verification_token', 'email_verification_sent_at'])
        return self.email_verification_token

    def verify_email(self, token):
        """Verify email with token."""
        if self.email_verification_token == token:
            # Check if token is not expired (24 hours)
            if self.email_verification_sent_at:
                expiry = self.email_verification_sent_at + timezone.timedelta(hours=24)
                if timezone.now() > expiry:
                    return False

            self.is_email_verified = True
            self.email_verification_token = ''
            self.status = self.Status.ACTIVE
            self.save(update_fields=['is_email_verified', 'email_verification_token', 'status'])
            return True
        return False

    def generate_password_reset_token(self):
        """Generate a secure password reset token."""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_sent_at = timezone.now()
        self.save(update_fields=['password_reset_token', 'password_reset_sent_at'])
        return self.password_reset_token

    def reset_password(self, token, new_password):
        """Reset password with token."""
        if self.password_reset_token == token:
            # Check if token is not expired (1 hour)
            if self.password_reset_sent_at:
                expiry = self.password_reset_sent_at + timezone.timedelta(hours=1)
                if timezone.now() > expiry:
                    return False

            self.set_password(new_password)
            self.password_reset_token = ''
            self.password_changed_at = timezone.now()
            self.save(update_fields=['password', 'password_reset_token', 'password_changed_at'])
            return True
        return False

    def update_last_login(self, ip_address=None):
        """Update last login information."""
        self.last_login = timezone.now()
        if ip_address:
            self.last_login_ip = ip_address
        self.reset_failed_login()
        self.save(update_fields=['last_login', 'last_login_ip'])

    def soft_delete(self):
        """Soft delete the user."""
        self.deleted_at = timezone.now()
        self.is_active = False
        self.email = f'deleted_{self.id}_{self.email}'
        self.save(update_fields=['deleted_at', 'is_active', 'email'])


class UserProfile(TimestampMixin):
    """
    Extended user profile for additional information.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )

    # Location
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, default='Nigeria')

    # Professional info
    occupation = models.CharField(max_length=100, blank=True)
    organization = models.CharField(max_length=200, blank=True)
    linkedin_url = models.URLField(blank=True)

    # Preferences
    notification_email = models.BooleanField(default=True)
    notification_sms = models.BooleanField(default=False)
    notification_push = models.BooleanField(default=True)

    # Timezone preference
    timezone = models.CharField(max_length=50, default='Africa/Lagos')

    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f'{self.user.full_name} Profile'


class UserSession(TimestampMixin):
    """
    Track user sessions for security and analytics.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    session_key = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    device_type = models.CharField(max_length=50, blank=True)
    location = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = 'user_sessions'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.email} - {self.ip_address}'

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class LoginHistory(models.Model):
    """
    Track login attempts for security auditing.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='login_history',
        null=True,
        blank=True
    )
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'login_history'
        verbose_name = 'Login History'
        verbose_name_plural = 'Login History'
        ordering = ['-created_at']

    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f'{self.email} - {status} - {self.created_at}'
