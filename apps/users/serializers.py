"""
User Serializers

Serializers for user authentication, registration, and profile management.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, UserProfile, MentorKYC, EagletProfile, MenteeKYC
from .constants import (
    EXPERTISE_CHOICES, MENTORSHIP_INTEREST_CHOICES,
    EDUCATIONAL_LEVEL_CHOICES, MENTORSHIP_GOAL_CHOICES, AGE_GROUP_CHOICES,
    MENTORSHIP_TYPE_CHOICES, MARITAL_STATUS_CHOICES, EMPLOYMENT_STATUS_CHOICES,
)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom token serializer that includes additional user data in the response.
    """

    def validate(self, attrs):
        email = attrs.get('email', '').lower()
        password = attrs.get('password')

        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'detail': 'Invalid email or password.'
            })

        # Check if account is locked
        if user.is_account_locked:
            raise serializers.ValidationError({
                'detail': 'Account is temporarily locked due to too many failed login attempts. Please try again later.'
            })

        # Check if account is active
        if not user.is_active:
            raise serializers.ValidationError({
                'detail': 'This account has been deactivated.'
            })

        # Check if user registered via OAuth and has no password
        if user.google_id and not user.has_usable_password():
            raise serializers.ValidationError({
                'detail': 'This account was created with Google Sign-In. Please use "Continue with Google" to log in.'
            })

        # Authenticate
        user = authenticate(
            request=self.context.get('request'),
            email=email,
            password=password
        )

        if not user:
            # Increment failed login attempt
            try:
                failed_user = User.objects.get(email=email)
                failed_user.increment_failed_login()
            except User.DoesNotExist:
                pass

            raise serializers.ValidationError({
                'detail': 'Invalid email or password.'
            })

        # Check email verification
        if not user.is_email_verified:
            raise serializers.ValidationError({
                'detail': 'Please verify your email address before logging in.'
            })

        # Reset failed login counter and update last login
        request = self.context.get('request')
        ip_address = None
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')

        user.update_last_login(ip_address)

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data,
        }


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user data.
    """

    full_name = serializers.CharField(read_only=True)
    kyc_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'role', 'status', 'avatar', 'bio',
            'is_email_verified', 'is_phone_verified', 'date_of_birth',
            'is_staff', 'is_superuser', 'kyc_status',
            'created_at', 'last_login',
        ]
        read_only_fields = [
            'id', 'email', 'role', 'status', 'is_email_verified',
            'is_phone_verified', 'is_staff', 'is_superuser', 'kyc_status',
            'created_at', 'last_login',
        ]

    def get_kyc_status(self, obj):
        """Get KYC status for both eagle and eaglet users."""
        if obj.role == 'eagle':
            kyc = MentorKYC.objects.filter(user=obj).first()
            return kyc.status if kyc else None
        elif obj.role == 'eaglet':
            kyc = MenteeKYC.objects.filter(user=obj).first()
            return kyc.status if kyc else None
        return None


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """

    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    role = serializers.ChoiceField(
        choices=[User.Role.EAGLE, User.Role.EAGLET],
        required=True
    )
    terms_accepted = serializers.BooleanField(required=True)

    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'last_name', 'phone_number',
            'password', 'password_confirm', 'role', 'terms_accepted',
        ]

    def validate_email(self, value):
        email = value.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                'A user with this email already exists.'
            )
        return email

    def validate_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })

        if not attrs.get('terms_accepted'):
            raise serializers.ValidationError({
                'terms_accepted': 'You must accept the terms and conditions.'
            })

        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        validated_data.pop('terms_accepted')
        password = validated_data.pop('password')
        role = validated_data.get('role')

        user = User.objects.create_user(
            password=password,
            terms_accepted_at=timezone.now(),
            privacy_accepted_at=timezone.now(),
            **validated_data
        )

        # Generate email verification token
        user.generate_email_verification_token()

        # Create user profile
        UserProfile.objects.create(user=user)

        # Create role-specific KYC profile (both require admin approval)
        if role == User.Role.EAGLE:
            # Create MentorKYC for Eagle (mentor) users
            MentorKYC.objects.create(user=user)
        elif role == User.Role.EAGLET:
            # Create MenteeKYC for Eaglet (mentee) users (NEW: requires approval)
            MenteeKYC.objects.create(user=user)
            # Also create legacy EagletProfile for backward compatibility
            EagletProfile.objects.create(user=user)

        return user


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing password.
    """

    old_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match.'
            })

        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({
                'old_password': 'Current password is incorrect.'
            })

        return attrs

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.password_changed_at = timezone.now()
        user.save(update_fields=['password', 'password_changed_at'])
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting password reset.
    """

    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming password reset.
    """

    token = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match.'
            })
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification.
    """

    token = serializers.CharField(required=True)


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile.
    """

    class Meta:
        model = UserProfile
        fields = [
            'city', 'state', 'country', 'occupation', 'organization',
            'linkedin_url', 'notification_email', 'notification_sms',
            'notification_push', 'timezone',
        ]


# =============================================================================
# MENTOR KYC SERIALIZERS
# =============================================================================

class MentorKYCSerializer(serializers.ModelSerializer):
    """
    Full KYC serializer for reading and updating KYC data.
    """

    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_date_of_birth = serializers.DateField(source='user.date_of_birth', read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)

    class Meta:
        model = MentorKYC
        fields = [
            'id', 'status', 'current_step', 'completion_percentage', 'is_complete',
            # User info (read-only)
            'user_first_name', 'user_last_name', 'user_date_of_birth',
            # Step 1: Personal Identification
            'government_id', 'government_id_type', 'government_id_verified',
            # Step 2: Ministry Background
            'church_name', 'church_role', 'years_of_service',
            'spiritual_testimony', 'recommendation_letter',
            # Step 3: Professional Experience
            'area_of_expertise', 'current_occupation',
            'linkedin_url', 'mentorship_interests',
            # Step 4: Consent & Submission
            'background_check_consent', 'code_of_conduct_agreed',
            'statement_of_faith_agreed', 'digital_signature', 'consent_date',
            # Timestamps
            'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'status', 'government_id_verified',
            'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]


class MentorKYCStep1Serializer(serializers.Serializer):
    """
    Step 1: Personal Identification
    Updates user's date_of_birth and KYC's government_id_type.
    """

    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)
    date_of_birth = serializers.DateField()
    government_id_type = serializers.CharField(max_length=50, required=False)

    def validate_date_of_birth(self, value):
        """Ensure user is at least 18 years old."""
        from datetime import date
        today = date.today()
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
        if age < 18:
            raise serializers.ValidationError('You must be at least 18 years old.')
        return value

    def save(self, user, kyc):
        """Update user and KYC with step 1 data."""
        user.first_name = self.validated_data['first_name']
        user.last_name = self.validated_data['last_name']
        user.date_of_birth = self.validated_data['date_of_birth']
        user.save(update_fields=['first_name', 'last_name', 'date_of_birth'])

        if 'government_id_type' in self.validated_data:
            kyc.government_id_type = self.validated_data['government_id_type']

        kyc.current_step = max(kyc.current_step, 2)
        kyc.save(update_fields=['government_id_type', 'current_step'])

        return kyc


class MentorKYCStep2Serializer(serializers.Serializer):
    """
    Step 2: Ministry Background
    """

    church_name = serializers.CharField(max_length=200)
    church_role = serializers.CharField(max_length=100)
    years_of_service = serializers.IntegerField(min_value=0, max_value=50)
    spiritual_testimony = serializers.CharField(min_length=100, max_length=2500)

    def validate_spiritual_testimony(self, value):
        """Ensure testimony has minimum content."""
        word_count = len(value.split())
        if word_count < 20:
            raise serializers.ValidationError(
                'Please provide a more detailed testimony (at least 20 words).'
            )
        return value

    def save(self, kyc):
        """Update KYC with step 2 data."""
        kyc.church_name = self.validated_data['church_name']
        kyc.church_role = self.validated_data['church_role']
        kyc.years_of_service = self.validated_data['years_of_service']
        kyc.spiritual_testimony = self.validated_data['spiritual_testimony']
        kyc.current_step = max(kyc.current_step, 3)
        kyc.save(update_fields=[
            'church_name', 'church_role', 'years_of_service',
            'spiritual_testimony', 'current_step'
        ])
        return kyc


class MentorKYCStep3Serializer(serializers.Serializer):
    """
    Step 3: Professional Experience
    """

    area_of_expertise = serializers.ChoiceField(choices=EXPERTISE_CHOICES)
    current_occupation = serializers.CharField(max_length=200)
    linkedin_url = serializers.URLField(required=False, allow_blank=True)
    mentorship_interests = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_INTEREST_CHOICES),
        min_length=1,
        max_length=8
    )

    def validate_linkedin_url(self, value):
        """Validate LinkedIn URL format."""
        if value and 'linkedin.com' not in value.lower():
            raise serializers.ValidationError(
                'Please provide a valid LinkedIn URL.'
            )
        return value

    def save(self, kyc):
        """Update KYC with step 3 data."""
        kyc.area_of_expertise = self.validated_data['area_of_expertise']
        kyc.current_occupation = self.validated_data['current_occupation']
        kyc.linkedin_url = self.validated_data.get('linkedin_url', '')
        kyc.mentorship_interests = self.validated_data['mentorship_interests']
        kyc.current_step = max(kyc.current_step, 4)
        kyc.save(update_fields=[
            'area_of_expertise', 'current_occupation',
            'linkedin_url', 'mentorship_interests', 'current_step'
        ])
        return kyc


class MentorKYCStep4Serializer(serializers.Serializer):
    """
    Step 4: Consent & Submission
    """

    background_check_consent = serializers.BooleanField()
    code_of_conduct_agreed = serializers.BooleanField()
    statement_of_faith_agreed = serializers.BooleanField()
    digital_signature = serializers.CharField(min_length=3, max_length=200)

    def validate(self, attrs):
        """Ensure all consent checkboxes are checked."""
        if not attrs.get('background_check_consent'):
            raise serializers.ValidationError({
                'background_check_consent': 'You must consent to a background check.'
            })
        if not attrs.get('code_of_conduct_agreed'):
            raise serializers.ValidationError({
                'code_of_conduct_agreed': 'You must agree to the code of conduct.'
            })
        if not attrs.get('statement_of_faith_agreed'):
            raise serializers.ValidationError({
                'statement_of_faith_agreed': 'You must agree to the statement of faith.'
            })
        return attrs

    def save(self, kyc):
        """Update KYC with step 4 data."""
        kyc.background_check_consent = self.validated_data['background_check_consent']
        kyc.code_of_conduct_agreed = self.validated_data['code_of_conduct_agreed']
        kyc.statement_of_faith_agreed = self.validated_data['statement_of_faith_agreed']
        kyc.digital_signature = self.validated_data['digital_signature']
        kyc.consent_date = timezone.now()
        kyc.save(update_fields=[
            'background_check_consent', 'code_of_conduct_agreed',
            'statement_of_faith_agreed', 'digital_signature', 'consent_date'
        ])
        return kyc


class MentorKYCAdminSerializer(serializers.ModelSerializer):
    """
    Serializer for admin to review and update KYC applications.
    """

    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)

    class Meta:
        model = MentorKYC
        fields = [
            'id', 'user_email', 'user_full_name', 'status',
            'government_id', 'government_id_verified',
            'church_name', 'church_role', 'years_of_service', 'spiritual_testimony',
            'recommendation_letter',
            'area_of_expertise', 'current_occupation', 'linkedin_url', 'mentorship_interests',
            'background_check_consent', 'code_of_conduct_agreed', 'statement_of_faith_agreed',
            'submitted_at', 'reviewed_at', 'reviewed_by', 'review_notes', 'rejection_reason',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'user_email', 'user_full_name',
            'government_id', 'church_name', 'church_role', 'years_of_service',
            'spiritual_testimony', 'recommendation_letter',
            'area_of_expertise', 'current_occupation', 'linkedin_url', 'mentorship_interests',
            'background_check_consent', 'code_of_conduct_agreed', 'statement_of_faith_agreed',
            'submitted_at', 'created_at', 'updated_at',
        ]


class MentorKYCListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for listing KYC applications in admin panel.
    """

    user_id = serializers.UUIDField(source='user.id', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    user_avatar = serializers.ImageField(source='user.avatar', read_only=True)
    user_profile_picture_url = serializers.URLField(source='user.profile_picture_url', read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    days_pending = serializers.SerializerMethodField()
    priority = serializers.SerializerMethodField()

    class Meta:
        model = MentorKYC
        fields = [
            'id', 'user_id', 'user_email', 'user_full_name',
            'user_avatar', 'user_profile_picture_url',
            'status', 'current_step', 'completion_percentage',
            'area_of_expertise', 'church_name',
            'submitted_at', 'days_pending', 'priority',
            'created_at',
        ]

    def get_days_pending(self, obj):
        """Calculate days since submission."""
        if obj.submitted_at:
            from django.utils import timezone
            delta = timezone.now() - obj.submitted_at
            return delta.days
        return None

    def get_priority(self, obj):
        """Determine priority based on wait time."""
        days = self.get_days_pending(obj)
        if days is None:
            return 'low'
        if days >= 5:
            return 'high'
        if days >= 3:
            return 'medium'
        return 'low'


class MentorKYCDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for admin to review a single KYC application.
    """

    # User information
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_phone_number = serializers.CharField(source='user.phone_number', read_only=True)
    user_avatar = serializers.ImageField(source='user.avatar', read_only=True)
    user_profile_picture_url = serializers.URLField(source='user.profile_picture_url', read_only=True)
    user_date_of_birth = serializers.DateField(source='user.date_of_birth', read_only=True)
    user_is_email_verified = serializers.BooleanField(source='user.is_email_verified', read_only=True)
    user_created_at = serializers.DateTimeField(source='user.created_at', read_only=True)

    # Computed fields
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)
    days_pending = serializers.SerializerMethodField()

    # Reviewer info
    reviewed_by_name = serializers.CharField(source='reviewed_by.full_name', read_only=True, allow_null=True)

    class Meta:
        model = MentorKYC
        fields = [
            'id',
            # User info
            'user_id', 'user_email', 'user_full_name', 'user_first_name', 'user_last_name',
            'user_phone_number', 'user_avatar', 'user_profile_picture_url',
            'user_date_of_birth', 'user_is_email_verified', 'user_created_at',
            # Step 1: Personal Identification
            'government_id', 'government_id_type', 'government_id_verified',
            # Step 2: Ministry Background
            'church_name', 'church_role', 'years_of_service',
            'spiritual_testimony', 'recommendation_letter',
            # Step 3: Professional Experience
            'area_of_expertise', 'current_occupation',
            'linkedin_url', 'mentorship_interests',
            # Step 4: Consent
            'background_check_consent', 'code_of_conduct_agreed',
            'statement_of_faith_agreed', 'digital_signature', 'consent_date',
            # Status & Review
            'status', 'current_step', 'completion_percentage', 'is_complete',
            'submitted_at', 'reviewed_at', 'reviewed_by', 'reviewed_by_name',
            'review_notes', 'rejection_reason', 'days_pending',
            'created_at', 'updated_at',
        ]

    def get_days_pending(self, obj):
        """Calculate days since submission."""
        if obj.submitted_at:
            from django.utils import timezone
            delta = timezone.now() - obj.submitted_at
            return delta.days
        return None


class KYCApprovalSerializer(serializers.Serializer):
    """Serializer for approving a KYC application."""

    review_notes = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class KYCRejectionSerializer(serializers.Serializer):
    """Serializer for rejecting a KYC application."""

    rejection_reason = serializers.CharField(required=True, min_length=10, max_length=1000)
    review_notes = serializers.CharField(required=False, allow_blank=True, max_length=1000)


class KYCRequestChangesSerializer(serializers.Serializer):
    """Serializer for requesting changes on a KYC application."""

    review_notes = serializers.CharField(required=True, min_length=10, max_length=2000)


class AdminInternalNoteSerializer(serializers.Serializer):
    """Serializer for adding internal notes to a KYC application."""

    note = serializers.CharField(required=True, min_length=1, max_length=1000)


class ResendVerificationSerializer(serializers.Serializer):
    """
    Serializer for resending email verification.
    """

    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return value.lower()


# =============================================================================
# EAGLET (MENTEE) PROFILE SERIALIZERS
# =============================================================================

class EagletProfileSerializer(serializers.ModelSerializer):
    """
    Full Eaglet profile serializer for reading and updating profile data.
    """

    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    profile_completeness = serializers.IntegerField(read_only=True)

    class Meta:
        model = EagletProfile
        fields = [
            'id',
            # User info (read-only)
            'user_first_name', 'user_last_name', 'user_email',
            # Personal info
            'age_group',
            # Educational background
            'educational_level', 'field_of_study', 'institution',
            # Mentorship preferences
            'interests', 'goals', 'preferred_mentor_expertise',
            # Profile content
            'bio', 'expectations',
            # Tracking
            'onboarding_completed', 'onboarding_completed_at',
            'profile_completeness',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'user_first_name', 'user_last_name', 'user_email',
            'onboarding_completed', 'onboarding_completed_at',
            'profile_completeness', 'created_at', 'updated_at',
        ]


class EagletOnboardingSerializer(serializers.Serializer):
    """
    Serializer for eaglet onboarding - all optional fields for profile setup.
    """

    # Personal info
    age_group = serializers.ChoiceField(
        choices=AGE_GROUP_CHOICES,
        required=False,
        allow_blank=True
    )

    # Educational background
    educational_level = serializers.ChoiceField(
        choices=EDUCATIONAL_LEVEL_CHOICES,
        required=False,
        allow_blank=True
    )
    field_of_study = serializers.CharField(max_length=200, required=False, allow_blank=True)
    institution = serializers.CharField(max_length=200, required=False, allow_blank=True)

    # Mentorship preferences
    interests = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_INTEREST_CHOICES),
        required=False,
        max_length=10
    )
    goals = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_GOAL_CHOICES),
        required=False,
        max_length=5
    )
    preferred_mentor_expertise = serializers.ListField(
        child=serializers.ChoiceField(choices=EXPERTISE_CHOICES),
        required=False,
        max_length=5
    )

    # Profile content
    bio = serializers.CharField(max_length=500, required=False, allow_blank=True)
    expectations = serializers.CharField(max_length=1000, required=False, allow_blank=True)

    def save(self, eaglet_profile):
        """Update eaglet profile with onboarding data."""
        update_fields = []

        for field in ['age_group', 'educational_level', 'field_of_study',
                      'institution', 'interests', 'goals',
                      'preferred_mentor_expertise', 'bio', 'expectations']:
            if field in self.validated_data:
                setattr(eaglet_profile, field, self.validated_data[field])
                update_fields.append(field)

        if update_fields:
            eaglet_profile.save(update_fields=update_fields)

        return eaglet_profile


class EagletCompleteOnboardingSerializer(serializers.Serializer):
    """
    Serializer for completing eaglet onboarding with required fields.
    """

    age_group = serializers.ChoiceField(choices=AGE_GROUP_CHOICES)
    educational_level = serializers.ChoiceField(choices=EDUCATIONAL_LEVEL_CHOICES)
    interests = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_INTEREST_CHOICES),
        min_length=1,
        max_length=10
    )
    goals = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_GOAL_CHOICES),
        min_length=1,
        max_length=5
    )

    # Optional fields
    field_of_study = serializers.CharField(max_length=200, required=False, allow_blank=True)
    institution = serializers.CharField(max_length=200, required=False, allow_blank=True)
    preferred_mentor_expertise = serializers.ListField(
        child=serializers.ChoiceField(choices=EXPERTISE_CHOICES),
        required=False,
        max_length=5
    )
    bio = serializers.CharField(max_length=500, required=False, allow_blank=True)
    expectations = serializers.CharField(max_length=1000, required=False, allow_blank=True)

    def save(self, eaglet_profile):
        """Update eaglet profile and mark onboarding as complete."""
        for field in ['age_group', 'educational_level', 'field_of_study',
                      'institution', 'interests', 'goals',
                      'preferred_mentor_expertise', 'bio', 'expectations']:
            if field in self.validated_data:
                setattr(eaglet_profile, field, self.validated_data[field])

        eaglet_profile.complete_onboarding()
        return eaglet_profile


# =============================================================================
# MENTEE KYC SERIALIZERS (NEW - Admin Approval Required)
# =============================================================================

class MenteeKYCSerializer(serializers.ModelSerializer):
    """
    Full KYC serializer for reading and updating Mentee KYC data.
    """

    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)

    class Meta:
        model = MenteeKYC
        fields = [
            'id', 'status', 'completion_percentage', 'is_complete',
            # User info (read-only)
            'user_first_name', 'user_last_name', 'user_email',
            # Personal Information
            'display_picture', 'national_id_number', 'marital_status',
            'country', 'city', 'location',
            # Contact
            'phone_number',
            # Professional
            'employment_status', 'linkedin_url', 'cv',
            # Profile
            'bio',
            # Preferences
            'mentorship_types',
            # Timestamps
            'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'status', 'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]


class MenteeKYCUpdateSerializer(serializers.Serializer):
    """
    Serializer for updating Mentee KYC data.
    """

    # Personal Information
    national_id_number = serializers.CharField(max_length=50, required=False)
    marital_status = serializers.ChoiceField(
        choices=MARITAL_STATUS_CHOICES,
        required=False
    )
    country = serializers.CharField(max_length=100, required=False)
    city = serializers.CharField(max_length=100, required=False)
    location = serializers.CharField(max_length=200, required=False, allow_blank=True)

    # Contact
    phone_number = serializers.CharField(max_length=20, required=False)

    # Professional
    employment_status = serializers.ChoiceField(
        choices=EMPLOYMENT_STATUS_CHOICES,
        required=False
    )
    linkedin_url = serializers.URLField(required=False, allow_blank=True)

    # Profile
    bio = serializers.CharField(min_length=50, required=False)

    # Preferences
    mentorship_types = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_TYPE_CHOICES),
        min_length=1,
        max_length=6,
        required=False
    )

    def validate_linkedin_url(self, value):
        """Validate LinkedIn URL format."""
        if value and 'linkedin.com' not in value.lower():
            raise serializers.ValidationError(
                'Please provide a valid LinkedIn URL.'
            )
        return value

    def save(self, mentee_kyc):
        """Update mentee KYC with provided data."""
        update_fields = []

        for field in ['national_id_number', 'marital_status', 'country', 'city',
                      'location', 'phone_number', 'employment_status',
                      'linkedin_url', 'bio', 'mentorship_types']:
            if field in self.validated_data:
                setattr(mentee_kyc, field, self.validated_data[field])
                update_fields.append(field)

        if update_fields:
            mentee_kyc.save(update_fields=update_fields)

        return mentee_kyc


class MenteeKYCListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for listing Mentee KYC applications in admin panel.
    """

    user_id = serializers.UUIDField(source='user.id', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    days_pending = serializers.SerializerMethodField()
    priority = serializers.SerializerMethodField()

    class Meta:
        model = MenteeKYC
        fields = [
            'id', 'user_id', 'user_email', 'user_full_name',
            'display_picture', 'status', 'completion_percentage',
            'country', 'city', 'employment_status',
            'submitted_at', 'days_pending', 'priority',
            'created_at',
        ]

    def get_days_pending(self, obj):
        """Calculate days since submission."""
        if obj.submitted_at:
            from django.utils import timezone
            delta = timezone.now() - obj.submitted_at
            return delta.days
        return None

    def get_priority(self, obj):
        """Determine priority based on wait time."""
        days = self.get_days_pending(obj)
        if days is None:
            return 'low'
        if days >= 5:
            return 'high'
        if days >= 3:
            return 'medium'
        return 'low'


class MenteeKYCDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for admin to review a single Mentee KYC application.
    """

    # User information
    user_id = serializers.UUIDField(source='user.id', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_is_email_verified = serializers.BooleanField(source='user.is_email_verified', read_only=True)
    user_created_at = serializers.DateTimeField(source='user.created_at', read_only=True)

    # Computed fields
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)
    days_pending = serializers.SerializerMethodField()

    # Reviewer info
    reviewed_by_name = serializers.CharField(source='reviewed_by.full_name', read_only=True, allow_null=True)

    class Meta:
        model = MenteeKYC
        fields = [
            'id',
            # User info
            'user_id', 'user_email', 'user_full_name', 'user_first_name', 'user_last_name',
            'user_is_email_verified', 'user_created_at',
            # Personal Information
            'display_picture', 'national_id_number', 'marital_status',
            'country', 'city', 'location',
            # Contact
            'phone_number',
            # Professional
            'employment_status', 'linkedin_url', 'cv',
            # Profile
            'bio',
            # Preferences
            'mentorship_types',
            # Status & Review
            'status', 'completion_percentage', 'is_complete',
            'submitted_at', 'reviewed_at', 'reviewed_by', 'reviewed_by_name',
            'review_notes', 'rejection_reason', 'days_pending',
            'created_at', 'updated_at',
        ]

    def get_days_pending(self, obj):
        """Calculate days since submission."""
        if obj.submitted_at:
            from django.utils import timezone
            delta = timezone.now() - obj.submitted_at
            return delta.days
        return None


# =============================================================================
# NEW MENTOR KYC SERIALIZERS (Updated with PM requirements)
# =============================================================================

class MentorKYCNewSerializer(serializers.ModelSerializer):
    """
    NEW KYC serializer for reading and updating Mentor KYC data (PM requirements).
    """

    user_first_name = serializers.CharField(source='user.first_name', read_only=True)
    user_last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_phone_number = serializers.CharField(source='user.phone_number', read_only=True)
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)

    class Meta:
        model = MentorKYC
        fields = [
            'id', 'status', 'completion_percentage', 'is_complete',
            # User info (read-only)
            'user_first_name', 'user_last_name', 'user_email', 'user_phone_number',
            # NEW: Personal Information
            'display_picture', 'location', 'national_id_number',
            'marital_status', 'employment_status',
            # NEW: Professional Profile
            'profile_description', 'cv', 'linkedin_url',
            # NEW: Specialization
            'mentorship_types',
            # Timestamps
            'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'status', 'submitted_at', 'reviewed_at', 'rejection_reason',
            'created_at', 'updated_at',
        ]


class MentorKYCNewUpdateSerializer(serializers.Serializer):
    """
    Serializer for updating Mentor KYC data (NEW PM requirements).
    """

    # Personal Information
    location = serializers.CharField(max_length=200, required=False)
    national_id_number = serializers.CharField(max_length=50, required=False)
    marital_status = serializers.ChoiceField(
        choices=MARITAL_STATUS_CHOICES,
        required=False
    )
    employment_status = serializers.ChoiceField(
        choices=EMPLOYMENT_STATUS_CHOICES,
        required=False
    )

    # Professional Profile
    profile_description = serializers.CharField(min_length=100, required=False)
    linkedin_url = serializers.URLField(required=False, allow_blank=True)

    # Specialization
    mentorship_types = serializers.ListField(
        child=serializers.ChoiceField(choices=MENTORSHIP_TYPE_CHOICES),
        min_length=1,
        max_length=6,
        required=False
    )

    def validate_linkedin_url(self, value):
        """Validate LinkedIn URL format."""
        if value and 'linkedin.com' not in value.lower():
            raise serializers.ValidationError(
                'Please provide a valid LinkedIn URL.'
            )
        return value

    def save(self, mentor_kyc, user):
        """Update mentor KYC and user with provided data."""
        kyc_update_fields = []
        user_update_fields = []

        # Update KYC fields
        for field in ['location', 'national_id_number', 'marital_status',
                      'employment_status', 'profile_description',
                      'linkedin_url', 'mentorship_types']:
            if field in self.validated_data:
                setattr(mentor_kyc, field, self.validated_data[field])
                kyc_update_fields.append(field)

        if kyc_update_fields:
            mentor_kyc.save(update_fields=kyc_update_fields)

        return mentor_kyc
