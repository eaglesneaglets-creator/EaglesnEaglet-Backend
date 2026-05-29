"""
Mentor KYC Submission Views

Auto-extracted from the monolithic views.py during Phase 11.5-04 split.
Trimmed of copy-paste import bloat (audit maintainability item) — keep
only what this file actually uses.
"""

import logging

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from core.permissions.roles import IsEagle

from ..models import MentorKYC
from ..serializers import (
    MentorKYCSerializer,
    MentorKYCStep1Serializer,
    MentorKYCStep2Serializer,
    MentorKYCStep3Serializer,
    MentorKYCStep4Serializer,
)

logger = logging.getLogger(__name__)


class MentorKYCView(APIView):
    """
    Get or update mentor KYC application.

    GET /api/v1/auth/kyc/
    PATCH /api/v1/auth/kyc/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get(self, request):
        kyc, created = MentorKYC.objects.get_or_create(user=request.user)

        return Response({
            'success': True,
            'data': MentorKYCSerializer(kyc).data
        })

    def patch(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = MentorKYCSerializer(kyc, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'success': True,
            'data': serializer.data
        })

class MentorKYCStepView(APIView):
    """
    Update a specific KYC step.

    PATCH /api/v1/auth/kyc/step/{step_number}/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def get_serializer_class(self, step_number):
        """Get the appropriate serializer for the step.

        Renamed local from `serializers` to `step_serializers` so it
        doesn't shadow the imported `rest_framework.serializers` module
        (flake8 F811).
        """
        step_serializers = {
            1: MentorKYCStep1Serializer,
            2: MentorKYCStep2Serializer,
            3: MentorKYCStep3Serializer,
            4: MentorKYCStep4Serializer,
        }
        return step_serializers.get(step_number)

    def patch(self, request, step_number):
        if step_number not in [1, 2, 3, 4]:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStep',
                    'message': 'Step number must be between 1 and 4.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer_class = self.get_serializer_class(step_number)
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save with the appropriate method
        if step_number == 1:
            serializer.save(user=request.user, kyc=kyc)
        else:
            serializer.save(kyc=kyc)

        return Response({
            'success': True,
            'data': MentorKYCSerializer(kyc).data,
            'message': f'Step {step_number} saved successfully.'
        })

class MentorKYCSubmitView(APIView):
    """
    Submit KYC application for review.

    POST /api/v1/auth/kyc/submit/
    """

    permission_classes = [IsAuthenticated, IsEagle]

    def post(self, request):
        try:
            kyc = MentorKYC.objects.get(user=request.user)
        except MentorKYC.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'KYC application not found. Please start the KYC process first.'
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Check if already submitted
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'AlreadySubmitted',
                    'message': 'Application has already been submitted.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Try to submit
        if kyc.submit():
            # Send confirmation email
            try:
                from ..tasks import send_kyc_submitted_email
                send_kyc_submitted_email.delay(str(request.user.id))
            except Exception:
                pass

            return Response({
                'success': True,
                'data': MentorKYCSerializer(kyc).data,
                'message': 'Application submitted successfully. Our team will review it within 2-3 business days.'
            })
        else:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'IncompleteApplication',
                    'message': 'Please complete all required fields before submitting.',
                    'details': {
                        'completion_percentage': kyc.completion_percentage
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)

class UploadGovernmentIDView(APIView):
    """
    Upload government ID document.

    POST /api/v1/auth/kyc/upload/government-id/
    """

    permission_classes = [IsAuthenticated, IsEagle]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES.get('government_id')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file size (10MB max)
        if file.size > 10 * 1024 * 1024:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'FileTooLarge',
                    'message': 'File size must be less than 10MB.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file type
        allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
        if file.content_type not in allowed_types:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFileType',
                    'message': 'File must be PDF, JPG, or PNG.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'government_ids')
        except Exception as exc:
            logger.error("Cloudinary upload failed for government_id (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(government_id=secure_url)

        return Response({
            'success': True,
            'data': {
                'government_id': secure_url
            },
            'message': 'Government ID uploaded successfully.'
        })

class UploadRecommendationView(APIView):
    """
    Upload recommendation letter.

    POST /api/v1/auth/kyc/upload/recommendation/
    """

    permission_classes = [IsAuthenticated, IsEagle]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        kyc, _ = MentorKYC.objects.get_or_create(user=request.user)

        # Don't allow modifications to submitted applications
        if kyc.status in ['submitted', 'under_review', 'approved']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ApplicationLocked',
                    'message': 'Cannot modify a submitted application.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        file = request.FILES.get('recommendation_letter')
        if not file:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'NoFile',
                    'message': 'No file uploaded.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file size (10MB max)
        if file.size > 10 * 1024 * 1024:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'FileTooLarge',
                    'message': 'File size must be less than 10MB.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file type
        allowed_types = ['application/pdf', 'application/msword',
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        if file.content_type not in allowed_types:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidFileType',
                    'message': 'File must be PDF or Word document.'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Upload to Cloudinary and store the secure_url directly
        from core.storage import upload_to_cloudinary
        try:
            result = upload_to_cloudinary(file, 'recommendations')
        except Exception as exc:
            logger.error("Cloudinary upload failed for recommendation (user %s): %s", request.user.id, exc)
            return Response({
                'success': False,
                'error': {'code': 503, 'type': 'UploadFailed', 'message': 'File upload failed. Please try again.'}
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        secure_url = result.get('secure_url')
        if secure_url:
            type(kyc).objects.filter(pk=kyc.pk).update(recommendation_letter=secure_url)

        return Response({
            'success': True,
            'data': {
                'recommendation_letter': secure_url
            },
            'message': 'Recommendation letter uploaded successfully.'
        })


# =============================================================================
# EAGLET (MENTEE) PROFILE VIEWS
# =============================================================================
