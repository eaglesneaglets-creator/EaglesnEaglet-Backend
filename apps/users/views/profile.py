"""
User Profile + Onboarding + Upload Views

Auto-extracted from monolithic views.py during Phase 11.5-04 split.
"""

import logging

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from core.permissions.roles import IsEagle, IsEaglet

logger = logging.getLogger(__name__)

from ..models import MentorKYC, MenteeKYC, EagletProfile
from ..serializers import (
    EagletProfileSerializer,
    EagletOnboardingSerializer,
    EagletCompleteOnboardingSerializer,
    MentorKYCNewSerializer,
    MentorKYCNewUpdateSerializer,
    MenteeKYCSerializer,
    MenteeKYCUpdateSerializer,
)
from ..validators import validate_cv_file, validate_image_file

# ─── Post-approval KYC edit policy (two-tier, v1) ───────────────────────────
# Approved profiles may edit contact/preference data freely from the Settings
# Profile section. Identity fields (and the immutable Code of Conduct
# snapshot) stay locked — changing those requires contacting support until a
# re-verification pipeline exists.

MENTOR_APPROVED_SAFE_FIELDS = {
    'location', 'marital_status', 'employment_status', 'phone_number',
    'profile_description', 'linkedin_url', 'mentorship_types',
}
MENTEE_APPROVED_SAFE_FIELDS = {
    'marital_status', 'country', 'city', 'location', 'phone_number',
    'employment_status', 'linkedin_url', 'bio', 'mentorship_types',
}


def _locked_field_response(locked_fields):
    """400 response naming the identity fields an approved user tried to edit.

    The whole payload is rejected (no partial application) so a mixed
    safe+locked PATCH never half-applies.
    """
    return Response({
        'success': False,
        'error': {
            'code': 400,
            'type': 'IdentityFieldLocked',
            'message': (
                'Identity details are locked after approval. '
                'Contact support to change them.'
            ),
            'details': {'locked_fields': sorted(locked_fields)},
        },
    }, status=status.HTTP_400_BAD_REQUEST)


class EagletProfileView(APIView):
    """
    Get or update eaglet profile.

    GET /api/v1/auth/eaglet/profile/
    PATCH /api/v1/auth/eaglet/profile/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def get(self, request):
        profile, created = EagletProfile.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data
        })

    def patch(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        serializer = EagletOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(eaglet_profile=profile)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data
        })

class EagletOnboardingView(APIView):
    """
    Complete eaglet onboarding.

    POST /api/v1/auth/eaglet/onboarding/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def post(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        # Check if already completed
        if profile.onboarding_completed:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadyCompleted',
                    'message': 'Onboarding has already been completed. Use PATCH /eaglet/profile/ to update your profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = EagletCompleteOnboardingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(eaglet_profile=profile)

        # Send welcome email
        try:
            from ..tasks import send_eaglet_welcome_email
            send_eaglet_welcome_email.delay(str(request.user.id))
        except Exception:
            pass

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data,
            'message': 'Welcome to Eagles & Eaglets! Your profile has been set up successfully.'
        })

class EagletSkipOnboardingView(APIView):
    """
    Skip eaglet onboarding for now.

    POST /api/v1/auth/eaglet/onboarding/skip/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def post(self, request):
        profile, _ = EagletProfile.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': EagletProfileSerializer(profile).data,
            'message': 'Onboarding skipped. You can complete your profile anytime from settings.'
        })


# =============================================================================
# NEW PROFILE/KYC VIEWS (PM Requirements - Both roles need approval)
# =============================================================================

class MentorProfileView(APIView):
    """
    Get or update mentor profile/KYC (NEW PM requirements).

    GET /api/v1/auth/mentor-profile/
    PATCH /api/v1/auth/mentor-profile/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get(self, request):
        kyc, created = MentorKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCNewSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Approved profiles: safe fields editable, identity fields locked.
        if kyc.status == 'approved':
            locked = set(request.data.keys()) - MENTOR_APPROVED_SAFE_FIELDS
            if locked:
                return _locked_field_response(locked)

        # Allow editing for draft, rejected, and requires_changes status
        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationPending',
                    'message': 'Your profile is currently under review. Please wait for admin feedback.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MentorKYCNewUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentor_kyc=kyc, user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCNewSerializer(kyc).data,
            'message': 'Profile updated successfully.'
        })

class MenteeProfileView(APIView):
    """
    Get or update mentee profile/KYC (NEW PM requirements).

    GET /api/v1/auth/mentee-profile/
    PATCH /api/v1/auth/mentee-profile/
    """

    permission_classes = [IsAuthenticated, IsEaglet]

    def get(self, request):
        kyc, created = MenteeKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MenteeKYCSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MenteeKYC.objects.get_or_create(user=request.user)

        # Approved profiles: safe fields editable, identity fields locked.
        if kyc.status == 'approved':
            locked = set(request.data.keys()) - MENTEE_APPROVED_SAFE_FIELDS
            if locked:
                return _locked_field_response(locked)

        # Allow editing for draft, rejected, and requires_changes status
        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationPending',
                    'message': 'Your profile is currently under review. Please wait for admin feedback.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MenteeKYCUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentee_kyc=kyc)

        return Response({
            'success': True,
            'data': MenteeKYCSerializer(kyc).data,
            'message': 'Profile updated successfully.'
        })

class ProfileSubmitView(APIView):
    """
    Submit profile/KYC for admin review (works for both Eagles and Eaglets).

    POST /api/v1/auth/profile/submit/
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.is_eagle:
            return self._submit_mentor_profile(request)
        elif user.is_eaglet:
            return self._submit_mentee_profile(request)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'Profile submission is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

    def _submit_mentor_profile(self, request):
        """Submit mentor KYC for review."""
        try:
            kyc = MentorKYC.objects.get(user=request.user)
        except MentorKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'Profile not found. Please complete your profile first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Your profile has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit using the model's submit method
        if kyc.submit():
            # Send confirmation email
            try:
                from ..tasks import send_profile_submitted_email
                send_profile_submitted_email.delay(str(request.user.id), 'mentor')
            except Exception as e:
                logger.warning(f"Failed to send profile submitted email: {e}")

            return Response({
                'success': True,
                'data': MentorKYCNewSerializer(kyc).data,
                'message': 'Profile submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteProfile',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)

    def _submit_mentee_profile(self, request):
        """Submit mentee KYC for review."""
        try:
            kyc = MenteeKYC.objects.get(user=request.user)
        except MenteeKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'Profile not found. Please complete your profile first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Your profile has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit using the model's submit method
        if kyc.submit():
            # Send confirmation email
            try:
                from ..tasks import send_profile_submitted_email
                send_profile_submitted_email.delay(str(request.user.id), 'mentee')
            except Exception as e:
                logger.warning(f"Failed to send profile submitted email: {e}")

            return Response({
                'success': True,
                'data': MenteeKYCSerializer(kyc).data,
                'message': 'Profile submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteProfile',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)

class UploadDisplayPictureView(APIView):
    """
    Upload profile/display picture (works for both Eagles and Eaglets).

    POST /api/v1/auth/upload/picture/
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user

        # Get the appropriate KYC model
        if user.is_eagle:
            kyc, _ = MentorKYC.objects.get_or_create(user=user)
        elif user.is_eaglet:
            kyc, _ = MenteeKYC.objects.get_or_create(user=user)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'Picture upload is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if profile is locked
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfileLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfilePending',
                    'message': 'Your profile is under review. Wait for admin feedback to make changes.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get uploaded file
        file = request.FILES.get('file') or request.FILES.get('display_picture')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded. Please select an image file.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate the file using our validator
        try:
            validate_image_file(file)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFile',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload via Cloudinary with optimization
        from core.storage import upload_to_cloudinary, get_optimized_url
        try:
            result = upload_to_cloudinary(file, 'profile_pictures')
        except Exception as exc:
            logger.error("Cloudinary upload failed for display_picture (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        secure_url = result.get('secure_url')
        public_id = result.get('public_id')

        # Store secure_url directly — display_picture is now a URLField
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(display_picture=secure_url)

        return Response({
            'success': True,
            'data': {
                'display_picture': secure_url,
                'optimized_url': get_optimized_url(public_id, preset='profile') if public_id else None,
                'thumbnail_url': get_optimized_url(public_id, preset='thumbnail') if public_id else None,
            },
            'message': 'Profile picture uploaded successfully.'
        })

class AvatarView(APIView):
    """
    Profile avatar — upload or remove (Phase 32-01).

    POST   /api/v1/auth/me/avatar/   (multipart: avatar|file)
    DELETE /api/v1/auth/me/avatar/

    DELIBERATELY NO KYC STATUS CHECK. This is a *profile* field, not a KYC field.
    `UploadDisplayPictureView` above intentionally blocks once KYC is
    approved/submitted/under_review because `display_picture` is an identity
    verification artifact (a Phase 21 immutability contract) — but that lock meant
    every fully-onboarded user was unable to change their photo at all. Do NOT add a
    status gate here; the two concerns are separate by design.

    Storage: the Cloudinary URL is written to `profile_picture_url` (a URLField), not
    to `avatar` (an ImageField). Assigning an absolute URL to an ImageField makes
    Django treat it as a relative storage path, producing a mangled
    `.../media/https://res.cloudinary.com/...`. See `User.avatar_url`.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file = request.FILES.get('avatar') or request.FILES.get('file')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded. Please select an image file.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Reuse the project's existing image validator (JPG/PNG/WEBP + size cap)
        # rather than introducing a second, divergent standard.
        try:
            validate_image_file(file)
        except Exception as exc:
            return Response({
                'success': False,
                'error': {'code': 400, 'type': 'InvalidFile', 'message': str(exc)}
            }, status=status.HTTP_400_BAD_REQUEST)

        from core.storage import upload_to_cloudinary, get_optimized_url
        try:
            result = upload_to_cloudinary(file, 'profile_pictures')
        except Exception as exc:
            logger.error("Cloudinary avatar upload failed (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {
                    'code': 503,
                    'type': 'UploadFailed',
                    'message': 'File upload failed. Please try again.',
                }
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        secure_url = result.get('secure_url')
        public_id = result.get('public_id')

        if not secure_url:
            return Response({
                'success': False,
                'error': {
                    'code': 503,
                    'type': 'UploadFailed',
                    'message': 'Upload succeeded but no URL was returned. Please try again.',
                }
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        user = request.user
        user.profile_picture_url = secure_url
        user.save(update_fields=['profile_picture_url'])

        # Derived URLs are a nice-to-have, not part of the contract. The upload has
        # already succeeded and the avatar is saved by this point, so a Cloudinary
        # config/SDK problem here must NOT turn a successful upload into a 500 —
        # `avatar_url` alone is enough for every caller.
        def _optimized(preset):
            if not public_id:
                return None
            try:
                return get_optimized_url(public_id, preset=preset)
            except Exception as exc:
                logger.warning(
                    "Could not build %s URL for avatar (user %s): %s",
                    preset, user.id, exc,
                )
                return None

        return Response({
            'success': True,
            'data': {
                'avatar_url': user.avatar_url,
                'optimized_url': _optimized('profile'),
                'thumbnail_url': _optimized('thumbnail'),
            },
            'message': 'Profile picture updated.',
        })

    def delete(self, request):
        """Clear the uploaded avatar.

        Only clears what this endpoint owns. `avatar_url` then falls back down the
        chain (e.g. to the KYC verification photo) rather than jumping straight to
        initials — removing your upload should not erase a photo you never uploaded here.
        """
        user = request.user
        update_fields = []

        if user.profile_picture_url:
            user.profile_picture_url = ''
            update_fields.append('profile_picture_url')
        if user.avatar:
            user.avatar = None
            update_fields.append('avatar')

        if update_fields:
            user.save(update_fields=update_fields)

        return Response({
            'success': True,
            'data': {'avatar_url': user.avatar_url},
            'message': 'Profile picture removed.',
        })


class UploadCVView(APIView):
    """
    Upload CV document (works for both Eagles and Eaglets).

    POST /api/v1/auth/upload/cv/
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user

        # Get the appropriate KYC model
        if user.is_eagle:
            kyc, _ = MentorKYC.objects.get_or_create(user=user)
        elif user.is_eaglet:
            kyc, _ = MenteeKYC.objects.get_or_create(user=user)
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidRole',
                    'message': 'CV upload is only available for Eagles and Eaglets.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if profile is locked
        if kyc.status == 'approved':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfileLocked',
                    'message': 'Cannot modify an approved profile.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        if kyc.status in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ProfilePending',
                    'message': 'Your profile is under review. Wait for admin feedback to make changes.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get uploaded file
        file = request.FILES.get('file') or request.FILES.get('cv')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded. Please select a PDF or DOCX file.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate the file using our validator
        try:
            validate_cv_file(file)
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFile',
                    'message': str(e)
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'cvs')
        except Exception as exc:
            logger.error("Cloudinary upload failed for CV (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(cv=secure_url)

        return Response({
            'success': True,
            'data': {
                'cv': secure_url
            },
            'message': 'CV uploaded successfully.'
        })


# =============================================================================
# GOOGLE OAUTH VIEWS
# =============================================================================
