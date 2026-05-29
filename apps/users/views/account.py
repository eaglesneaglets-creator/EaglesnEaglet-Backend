"""
Account Settings — email change, account deletion.

Auto-extracted from the monolithic views.py during Phase 11.5-04 split.
Trimmed of the copy-paste import bloat from the original split (audit
maintainability item) — keep only what this file actually uses.
"""

import logging
import secrets
from datetime import timedelta

from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from ..models import User

logger = logging.getLogger(__name__)


class EmailChangeRequestView(APIView):
    """Request an email address change. Sends verification link to NEW address."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        from ..serializers import EmailChangeRequestSerializer
        from ..models import EmailChangeRequest
        from ..tasks import send_email_change_confirm, send_email_change_notice, EMAIL_CHANGE_EXPIRY_HOURS

        serializer = EmailChangeRequestSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        new_email = serializer.validated_data['new_email']
        raw_token = secrets.token_urlsafe(48)
        token_hash = EmailChangeRequest.hash_token(raw_token)
        expires_at = timezone.now() + timedelta(hours=EMAIL_CHANGE_EXPIRY_HOURS)

        EmailChangeRequest.objects.filter(
            user=request.user, consumed_at__isnull=True
        ).update(consumed_at=timezone.now())

        EmailChangeRequest.objects.create(
            user=request.user,
            new_email=new_email,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        send_email_change_confirm.delay(str(request.user.id), new_email, raw_token)
        send_email_change_notice.delay(str(request.user.id), new_email)

        return Response({
            'success': True,
            'message': f'Verification sent to {new_email}. Check your inbox to confirm.',
        })

class EmailChangeConfirmView(APIView):
    """Confirm email change via tokenized link. Public — user may not be logged in."""

    permission_classes = [AllowAny]

    def get(self, request, token):
        from ..models import EmailChangeRequest

        token_hash = EmailChangeRequest.hash_token(token)
        try:
            req = EmailChangeRequest.objects.select_related('user').get(token_hash=token_hash)
        except EmailChangeRequest.DoesNotExist:
            return Response(
                {'success': False, 'error': {'code': 400, 'type': 'InvalidToken', 'message': 'Link expired or already used.'}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not req.is_valid:
            return Response(
                {'success': False, 'error': {'code': 400, 'type': 'InvalidToken', 'message': 'Link expired or already used.'}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(email__iexact=req.new_email).exclude(pk=req.user_id).exists():
            req.consumed_at = timezone.now()
            req.save(update_fields=['consumed_at'])
            return Response(
                {'success': False, 'error': {'code': 400, 'type': 'EmailTaken', 'message': 'That email is no longer available.'}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = req.user
        user.email = req.new_email
        user.save(update_fields=['email'])

        req.consumed_at = timezone.now()
        req.save(update_fields=['consumed_at'])

        logger.info("User %s changed email to %s", user.id, user.email)

        return Response({
            'success': True,
            'message': 'Email updated. Please sign in with your new address.',
        })

class AccountDeleteView(APIView):
    """Soft-delete the authenticated user's account."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        from ..serializers import AccountDeleteSerializer

        serializer = AccountDeleteSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        user_id = user.id
        user.soft_delete()

        try:
            from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
            tokens = OutstandingToken.objects.filter(user_id=user_id)
            for t in tokens:
                BlacklistedToken.objects.get_or_create(token=t)
        except Exception as exc:
            logger.warning("Could not blacklist tokens for deleted user %s: %s", user_id, exc)

        logger.info("User %s soft-deleted account", user_id)

        return Response({'success': True, 'message': 'Account deleted.'})
