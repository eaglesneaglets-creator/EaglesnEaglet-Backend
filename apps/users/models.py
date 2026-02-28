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
from .validators import (
    validate_cv_file,
    validate_image_file,
    validate_linkedin_url,
    validate_ghana_phone,
    validate_national_id,
)
from .constants import (
    MENTORSHIP_TYPE_CHOICES,
    MARITAL_STATUS_CHOICES,
    EMPLOYMENT_STATUS_CHOICES,
    APPROVAL_STATUS_CHOICES,
)


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
        help_text='International phone number (e.g., +1 234 567 8900)'
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
    profile_picture_url = models.URLField(
        max_length=500,
        blank=True,
        help_text='External profile picture URL (from OAuth providers)'
    )

    # OAuth fields
    google_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text='Google OAuth user ID'
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
            # Check if token is not expired (15 minutes for security)
            if self.password_reset_sent_at:
                expiry = self.password_reset_sent_at + timezone.timedelta(minutes=15)
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


class MentorKYC(TimestampMixin):
    """
    KYC (Know Your Customer) verification data for Eagle (Mentor) applicants.
    Stores multi-step verification information required for mentor approval.
    """

    class VerificationStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        SUBMITTED = 'submitted', 'Submitted'
        UNDER_REVIEW = 'under_review', 'Under Review'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        REQUIRES_CHANGES = 'requires_changes', 'Requires Changes'

    # Primary identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to user
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='mentor_kyc'
    )

    # =========================================================================
    # NEW: Personal Information (PM Requirements)
    # =========================================================================
    display_picture = models.ImageField(
        upload_to='kyc/profile_pictures/%Y/%m/',
        blank=True,
        null=True,
        validators=[validate_image_file],
        help_text='Profile display picture (required)'
    )
    location = models.CharField(
        max_length=200,
        blank=True,
        help_text='City/Country location'
    )
    national_id_number = models.CharField(
        max_length=50,
        blank=True,
        validators=[validate_national_id],
        help_text='National ID number for KYC verification'
    )
    marital_status = models.CharField(
        max_length=20,
        choices=MARITAL_STATUS_CHOICES,
        blank=True,
        help_text='Marital status'
    )
    employment_status = models.CharField(
        max_length=30,
        choices=EMPLOYMENT_STATUS_CHOICES,
        blank=True,
        help_text='Employment status'
    )

    # =========================================================================
    # NEW: Professional Profile (PM Requirements)
    # =========================================================================
    profile_description = models.TextField(
        blank=True,
        help_text='Profile description / bio about mentor experience and expertise'
    )
    cv = models.FileField(
        upload_to='kyc/cvs/mentors/%Y/%m/',
        blank=True,
        null=True,
        validators=[validate_cv_file],
        help_text='Curriculum Vitae (PDF/DOCX)'
    )
    mentorship_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Types of mentorship offered (multi-select)'
    )

    # =========================================================================
    # LEGACY: Step 1: Personal Identification (kept for backward compatibility)
    # =========================================================================
    government_id = models.FileField(
        upload_to='kyc/government_ids/%Y/%m/',
        blank=True,
        null=True,
        help_text='[LEGACY] Government-issued ID (passport, driver\'s license, national ID)'
    )
    government_id_type = models.CharField(
        max_length=50,
        blank=True,
        help_text='[LEGACY] Type of government ID uploaded'
    )
    government_id_verified = models.BooleanField(default=False)

    # =========================================================================
    # Step 2: Ministry Background
    # =========================================================================
    church_name = models.CharField(
        max_length=200,
        blank=True,
        help_text='Current church or ministry name'
    )
    church_role = models.CharField(
        max_length=100,
        blank=True,
        help_text='Role/position in the church'
    )
    years_of_service = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text='Years of active service in ministry'
    )
    spiritual_testimony = models.TextField(
        max_length=2500,
        blank=True,
        help_text='Brief spiritual journey/testimony (max 500 words)'
    )
    recommendation_letter = models.FileField(
        upload_to='kyc/recommendations/%Y/%m/',
        blank=True,
        null=True,
        help_text='Recommendation letter from pastor or ministry leader'
    )

    # =========================================================================
    # Step 3: Professional Experience
    # =========================================================================
    area_of_expertise = models.CharField(
        max_length=100,
        blank=True,
        help_text='Primary area of expertise for mentoring'
    )
    current_occupation = models.CharField(
        max_length=200,
        blank=True,
        help_text='Current occupation or profession'
    )
    linkedin_url = models.URLField(
        blank=True,
        help_text='LinkedIn profile URL'
    )
    mentorship_interests = models.JSONField(
        default=list,
        blank=True,
        help_text='Topics comfortable mentoring in (stored as JSON array)'
    )

    # =========================================================================
    # Step 4: Consent & Submission
    # =========================================================================
    background_check_consent = models.BooleanField(
        default=False,
        help_text='Consent to background check'
    )
    code_of_conduct_agreed = models.BooleanField(
        default=False,
        help_text='Agreement to mentor code of conduct'
    )
    statement_of_faith_agreed = models.BooleanField(
        default=False,
        help_text='Agreement with statement of faith'
    )
    digital_signature = models.TextField(
        blank=True,
        help_text='Digital signature (typed name or base64 signature image)'
    )
    consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Date when consent was given'
    )

    # =========================================================================
    # Verification Tracking
    # =========================================================================
    status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.DRAFT
    )
    current_step = models.PositiveIntegerField(
        default=1,
        help_text='Current step in the KYC wizard (1-4)'
    )
    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the application was submitted'
    )
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the application was reviewed'
    )
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_kyc_applications',
        help_text='Admin who reviewed the application'
    )
    review_notes = models.TextField(
        blank=True,
        help_text='Internal notes from the reviewer'
    )
    rejection_reason = models.TextField(
        blank=True,
        help_text='Reason for rejection (shown to applicant)'
    )

    class Meta:
        db_table = 'mentor_kyc'
        verbose_name = 'Mentor KYC'
        verbose_name_plural = 'Mentor KYC Applications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['submitted_at']),
        ]

    def __str__(self):
        return f'{self.user.full_name} - KYC ({self.get_status_display()})'

    @property
    def is_complete(self):
        """Check if all required fields are filled for submission (NEW requirements)."""
        required_fields = [
            self.display_picture,
            self.location,
            self.user.phone_number,
            self.national_id_number,
            self.marital_status,
            self.employment_status,
            self.profile_description,
            self.cv,
            self.mentorship_types,
        ]
        return all(required_fields)

    @property
    def is_legacy_complete(self):
        """Check if all LEGACY required fields are filled (for backward compatibility)."""
        required_fields = [
            self.user.date_of_birth,
            self.government_id,
            self.church_name,
            self.years_of_service is not None,
            self.spiritual_testimony,
            self.area_of_expertise,
            self.current_occupation,
            self.mentorship_interests,
            self.background_check_consent,
            self.code_of_conduct_agreed,
            self.statement_of_faith_agreed,
            self.digital_signature,
        ]
        return all(required_fields)

    @property
    def completion_percentage(self):
        """Calculate the completion percentage of the KYC application (NEW requirements)."""
        fields_to_check = [
            bool(self.display_picture),
            bool(self.location),
            bool(self.user.phone_number),
            bool(self.national_id_number),
            bool(self.marital_status),
            bool(self.employment_status),
            bool(self.profile_description),
            bool(self.cv),
            bool(self.mentorship_types),
        ]
        completed = sum(fields_to_check)
        total = len(fields_to_check)
        return int((completed / total) * 100)

    def submit(self):
        """Submit the KYC application for review.

        Accepts either the NEW PM requirements OR the LEGACY requirements
        for backward compatibility with the existing KYC wizard.
        """
        # Accept either new requirements OR legacy requirements
        if self.is_complete or self.is_legacy_complete:
            self.status = self.VerificationStatus.SUBMITTED
            self.submitted_at = timezone.now()
            self.current_step = 4  # Mark as completed
            self.save(update_fields=['status', 'submitted_at', 'current_step'])
            return True
        return False

    def approve(self, reviewer):
        """Approve the KYC application."""
        self.status = self.VerificationStatus.APPROVED
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by'])

        # Update user status to active
        self.user.status = User.Status.ACTIVE
        self.user.save(update_fields=['status'])

    def reject(self, reviewer, reason):
        """Reject the KYC application."""
        self.status = self.VerificationStatus.REJECTED
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.rejection_reason = reason
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by', 'rejection_reason'])

    def request_changes(self, reviewer, notes):
        """Request changes to the KYC application."""
        self.status = self.VerificationStatus.REQUIRES_CHANGES
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.review_notes = notes
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by', 'review_notes'])


class EagletProfile(TimestampMixin):
    """
    Profile data for Eaglet (Mentee) users.
    This is optional profile information that helps match mentees with mentors.
    Unlike MentorKYC, this does not require admin approval.
    """

    class EducationalLevel(models.TextChoices):
        HIGH_SCHOOL = 'high_school', 'High School'
        UNDERGRADUATE = 'undergraduate', 'Undergraduate'
        GRADUATE = 'graduate', 'Graduate/Postgraduate'
        PROFESSIONAL = 'professional', 'Working Professional'
        OTHER = 'other', 'Other'

    class AgeGroup(models.TextChoices):
        AGE_13_17 = '13_17', '13-17 years'
        AGE_18_24 = '18_24', '18-24 years'
        AGE_25_34 = '25_34', '25-34 years'
        AGE_35_44 = '35_44', '35-44 years'
        AGE_45_PLUS = '45_plus', '45+ years'

    # Primary identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to user
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='eaglet_profile'
    )

    # =========================================================================
    # Personal Information
    # =========================================================================
    age_group = models.CharField(
        max_length=20,
        choices=AgeGroup.choices,
        blank=True,
        help_text='Age group for appropriate mentor matching'
    )

    # =========================================================================
    # Educational Background
    # =========================================================================
    educational_level = models.CharField(
        max_length=20,
        choices=EducationalLevel.choices,
        blank=True,
        help_text='Current educational level'
    )
    field_of_study = models.CharField(
        max_length=200,
        blank=True,
        help_text='Field of study or profession'
    )
    institution = models.CharField(
        max_length=200,
        blank=True,
        help_text='School, university, or workplace'
    )

    # =========================================================================
    # Mentorship Preferences
    # =========================================================================
    interests = models.JSONField(
        default=list,
        blank=True,
        help_text='Areas of interest for mentorship (stored as JSON array)'
    )
    goals = models.JSONField(
        default=list,
        blank=True,
        help_text='Mentorship goals (stored as JSON array)'
    )
    preferred_mentor_expertise = models.JSONField(
        default=list,
        blank=True,
        help_text='Preferred mentor expertise areas (stored as JSON array)'
    )

    # =========================================================================
    # Profile Content
    # =========================================================================
    bio = models.TextField(
        max_length=500,
        blank=True,
        help_text='Short bio about yourself'
    )
    expectations = models.TextField(
        max_length=1000,
        blank=True,
        help_text='What you hope to gain from mentorship'
    )

    # =========================================================================
    # Tracking
    # =========================================================================
    onboarding_completed = models.BooleanField(
        default=False,
        help_text='Whether the user has completed optional onboarding'
    )
    onboarding_completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When onboarding was completed'
    )

    class Meta:
        db_table = 'eaglet_profiles'
        verbose_name = 'Eaglet Profile'
        verbose_name_plural = 'Eaglet Profiles'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.full_name} - Eaglet Profile'

    @property
    def profile_completeness(self):
        """Calculate profile completeness percentage."""
        fields_to_check = [
            bool(self.age_group),
            bool(self.educational_level),
            bool(self.field_of_study),
            bool(self.interests),
            bool(self.goals),
            bool(self.bio),
        ]
        completed = sum(fields_to_check)
        total = len(fields_to_check)
        return int((completed / total) * 100)

    def complete_onboarding(self):
        """Mark onboarding as complete."""
        self.onboarding_completed = True
        self.onboarding_completed_at = timezone.now()
        self.save(update_fields=['onboarding_completed', 'onboarding_completed_at'])


class MenteeKYC(TimestampMixin):
    """
    KYC (Know Your Customer) verification data for Eaglet (Mentee) applicants.
    NEW: Mentees now require admin approval like mentors.
    """

    class VerificationStatus(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        SUBMITTED = 'submitted', 'Submitted'
        UNDER_REVIEW = 'under_review', 'Under Review'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        REQUIRES_CHANGES = 'requires_changes', 'Requires Changes'

    # Primary identifier
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to user
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='mentee_kyc'
    )

    # =========================================================================
    # Personal Information
    # =========================================================================
    display_picture = models.ImageField(
        upload_to='kyc/profile_pictures/%Y/%m/',
        blank=True,
        null=True,
        validators=[validate_image_file],
        help_text='Profile display picture (required)'
    )
    national_id_number = models.CharField(
        max_length=50,
        blank=True,
        validators=[validate_national_id],
        help_text='National ID number for KYC verification'
    )
    marital_status = models.CharField(
        max_length=20,
        choices=MARITAL_STATUS_CHOICES,
        blank=True,
        help_text='Marital status'
    )
    country = models.CharField(
        max_length=100,
        blank=True,
        help_text='Country of residence'
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        help_text='City of residence'
    )
    location = models.CharField(
        max_length=200,
        blank=True,
        help_text='Additional address details (optional)'
    )

    # =========================================================================
    # Contact Information
    # =========================================================================
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        validators=[validate_ghana_phone],
        help_text='Phone number (Ghana format: +233 XX XXX XXXX)'
    )

    # =========================================================================
    # Professional & Background
    # =========================================================================
    employment_status = models.CharField(
        max_length=30,
        choices=EMPLOYMENT_STATUS_CHOICES,
        blank=True,
        help_text='Current employment status'
    )
    linkedin_url = models.URLField(
        blank=True,
        validators=[validate_linkedin_url],
        help_text='LinkedIn profile URL (optional)'
    )
    cv = models.FileField(
        upload_to='kyc/cvs/mentees/%Y/%m/',
        blank=True,
        null=True,
        validators=[validate_cv_file],
        help_text='Curriculum Vitae (optional, PDF/DOCX)'
    )

    # =========================================================================
    # Profile Description
    # =========================================================================
    bio = models.TextField(
        blank=True,
        help_text='Personal bio / profile statement ("Write something about yourself — surprise us")'
    )

    # =========================================================================
    # Mentorship Preferences
    # =========================================================================
    mentorship_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Types of mentorship required (multi-select)'
    )

    # =========================================================================
    # Verification Tracking
    # =========================================================================
    status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.DRAFT
    )
    submitted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the application was submitted'
    )
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the application was reviewed'
    )
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_mentee_applications',
        help_text='Admin who reviewed the application'
    )
    review_notes = models.TextField(
        blank=True,
        help_text='Internal notes from the reviewer'
    )
    rejection_reason = models.TextField(
        blank=True,
        help_text='Reason for rejection (shown to applicant)'
    )

    class Meta:
        db_table = 'mentee_kyc'
        verbose_name = 'Mentee KYC'
        verbose_name_plural = 'Mentee KYC Applications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['submitted_at']),
        ]

    def __str__(self):
        return f'{self.user.full_name} - Mentee KYC ({self.get_status_display()})'

    @property
    def is_complete(self):
        """Check if all required fields are filled for submission."""
        required_fields = [
            self.display_picture,
            self.national_id_number,
            self.marital_status,
            self.country,
            self.city,
            self.phone_number,
            self.employment_status,
            self.bio,
            self.mentorship_types,
        ]
        return all(required_fields)

    @property
    def completion_percentage(self):
        """Calculate the completion percentage of the KYC application."""
        fields_to_check = [
            bool(self.display_picture),
            bool(self.national_id_number),
            bool(self.marital_status),
            bool(self.country),
            bool(self.city),
            bool(self.phone_number),
            bool(self.employment_status),
            bool(self.bio),
            bool(self.mentorship_types),
            # Optional fields (count as bonus)
            bool(self.linkedin_url),
            bool(self.cv),
            bool(self.location),
        ]
        # Only count required fields (first 9)
        required_completed = sum(fields_to_check[:9])
        return int((required_completed / 9) * 100)

    def submit(self):
        """Submit the KYC application for review."""
        if self.is_complete:
            self.status = self.VerificationStatus.SUBMITTED
            self.submitted_at = timezone.now()
            self.save(update_fields=['status', 'submitted_at'])
            return True
        return False

    def approve(self, reviewer):
        """Approve the KYC application."""
        self.status = self.VerificationStatus.APPROVED
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by'])

        # Update user status to active
        self.user.status = User.Status.ACTIVE
        self.user.save(update_fields=['status'])

    def reject(self, reviewer, reason):
        """Reject the KYC application."""
        self.status = self.VerificationStatus.REJECTED
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.rejection_reason = reason
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by', 'rejection_reason'])

    def request_changes(self, reviewer, notes):
        """Request changes to the KYC application."""
        self.status = self.VerificationStatus.REQUIRES_CHANGES
        self.reviewed_at = timezone.now()
        self.reviewed_by = reviewer
        self.review_notes = notes
        self.save(update_fields=['status', 'reviewed_at', 'reviewed_by', 'review_notes'])
