"""
Mentor Availability Schedule Views

Auto-extracted from monolithic views.py during Phase 11.5-04 split.
"""

import logging

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


logger = logging.getLogger(__name__)



class MentorAvailabilityView(APIView):
    """List and create availability slots for the authenticated Eagle."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from ..models import MentorAvailability
        from ..serializers import MentorAvailabilitySerializer
        slots = MentorAvailability.objects.filter(mentor=request.user, is_active=True)
        serializer = MentorAvailabilitySerializer(slots, many=True)
        return Response({'success': True, 'data': serializer.data})

    def post(self, request):
        from ..serializers import MentorAvailabilitySerializer
        if request.user.role != 'eagle':
            return Response({'success': False, 'error': {'message': 'Only Eagles can set availability.'}}, status=403)
        serializer = MentorAvailabilitySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(mentor=request.user)
        return Response({'success': True, 'data': serializer.data}, status=201)

class MentorAvailabilityDetailView(APIView):
    """Delete a specific availability slot."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, slot_id):
        from ..models import MentorAvailability
        try:
            slot = MentorAvailability.objects.get(id=slot_id, mentor=request.user)
        except MentorAvailability.DoesNotExist:
            return Response({'success': False, 'error': {'message': 'Slot not found.'}}, status=404)
        slot.delete()
        return Response({'success': True}, status=204)

class PublicMentorAvailabilityView(APIView):
    """Public read-only view of a mentor's availability (for Eaglets)."""
    permission_classes = []  # AllowAny

    def get(self, request, user_id):
        from ..models import MentorAvailability
        from ..serializers import MentorAvailabilitySerializer
        slots = MentorAvailability.objects.filter(mentor_id=user_id, is_active=True)
        serializer = MentorAvailabilitySerializer(slots, many=True)
        return Response({'success': True, 'data': serializer.data})


# =============================================================================
# Account Settings (Phase 11-02)
# =============================================================================

