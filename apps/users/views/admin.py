"""
Admin Views — KYC review, dashboard stats, user management

Auto-extracted from monolithic views.py during Phase 11.5-04 split.
"""

import logging

from django.db import models
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from core.permissions.roles import IsAdmin

logger = logging.getLogger(__name__)

from ..models import User, MentorKYC, MenteeKYC
from ..serializers import (
    MentorKYCListSerializer,
    MentorKYCDetailSerializer,
    KYCApprovalSerializer,
    KYCRejectionSerializer,
    KYCRequestChangesSerializer,
    AdminInternalNoteSerializer,
    MenteeKYCListSerializer,
    MenteeKYCDetailSerializer,
)


class AdminKYCListView(APIView):
    """
    List all KYC applications for admin review (both mentors and mentees).

    GET /api/v1/admin/kyc/
    Query params:
        - role: Filter by role (mentor, mentee, all) - defaults to 'all'
        - status: Filter by status (submitted, under_review, approved, rejected, requires_changes)
        - priority: Filter by priority (high, medium, low)
        - search: Search by user name or email
        - ordering: Sort by field (submitted_at, -submitted_at, created_at, -created_at)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Q, Count, Case, When

        role_filter = request.GET.get('role', 'all')
        status_filter = request.GET.get('status')
        search = request.GET.get('search')
        ordering = request.GET.get('ordering', '-submitted_at')
        page = int(request.GET.get('page', 1))
        per_page = min(int(request.GET.get('per_page', 20)), 100)

        # Build results based on role filter
        mentor_applications = []
        mentee_applications = []

        # Query mentors if needed
        if role_filter in ['mentor', 'all']:
            mentor_qs = MentorKYC.objects.select_related('user').all()

            if status_filter:
                if status_filter == 'pending':
                    mentor_qs = mentor_qs.filter(status__in=['submitted', 'under_review'])
                else:
                    mentor_qs = mentor_qs.filter(status=status_filter)

            if search:
                mentor_qs = mentor_qs.filter(
                    Q(user__email__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search)
                )

            mentor_applications = list(mentor_qs)

        # Query mentees if needed
        if role_filter in ['mentee', 'all']:
            mentee_qs = MenteeKYC.objects.select_related('user').all()

            if status_filter:
                if status_filter == 'pending':
                    mentee_qs = mentee_qs.filter(status__in=['submitted', 'under_review'])
                else:
                    mentee_qs = mentee_qs.filter(status=status_filter)

            if search:
                mentee_qs = mentee_qs.filter(
                    Q(user__email__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search)
                )

            mentee_applications = list(mentee_qs)

        # Serialize applications with role tag
        all_applications = []

        for kyc in mentor_applications:
            data = MentorKYCListSerializer(kyc).data
            data['role'] = 'mentor'
            data['role_display'] = 'Eagle (Mentor)'
            all_applications.append(data)

        for kyc in mentee_applications:
            data = MenteeKYCListSerializer(kyc).data
            data['role'] = 'mentee'
            data['role_display'] = 'Eaglet (Mentee)'
            all_applications.append(data)

        # Sort combined list
        reverse = ordering.startswith('-')
        sort_field = ordering.lstrip('-')
        if sort_field in ['submitted_at', 'created_at']:
            all_applications.sort(
                key=lambda x: x.get(sort_field) or '',
                reverse=reverse
            )

        # Pagination
        total = len(all_applications)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_applications[start:end]

        # Get summary counts using aggregate (2 queries instead of 14)
        def _get_status_counts(model):
            """Single-query aggregation for all status counts."""
            return model.objects.aggregate(
                total=Count('id'),
                pending=Count(Case(When(status__in=['submitted', 'under_review'], then=1))),
                approved=Count(Case(When(status='approved', then=1))),
                rejected=Count(Case(When(status='rejected', then=1))),
                requires_changes=Count(Case(When(status='requires_changes', then=1))),
            )

        mentor_counts = _get_status_counts(MentorKYC)
        mentee_counts = _get_status_counts(MenteeKYC)

        summary = {
            'total': mentor_counts['total'] + mentee_counts['total'],
            'pending': mentor_counts['pending'] + mentee_counts['pending'],
            'approved': mentor_counts['approved'] + mentee_counts['approved'],
            'rejected': mentor_counts['rejected'] + mentee_counts['rejected'],
            'requires_changes': mentor_counts['requires_changes'] + mentee_counts['requires_changes'],
            'mentors': {
                'total': mentor_counts['total'],
                'pending': mentor_counts['pending'],
            },
            'mentees': {
                'total': mentee_counts['total'],
                'pending': mentee_counts['pending'],
            },
        }

        return Response({
            'success': True,
            'data': {
                'applications': paginated,
                'summary': summary,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (total + per_page - 1) // per_page,
                }
            }
        })

class AdminKYCDetailView(APIView):
    """
    Get detailed KYC application for admin review (supports both mentor and mentee).

    GET /api/v1/admin/kyc/{kyc_id}/
    Query params:
        - role: 'mentor' or 'mentee' (required to identify which model to query)

    Note: This endpoint is read-only. To transition a KYC application from
    'submitted' to 'under_review', use the POST /admin/kyc/{kyc_id}/start-review/
    endpoint instead. GET requests must not have write side-effects per HTTP
    semantics (RFC 7231 §4.2.1).
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request, kyc_id):
        role = request.GET.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user', 'reviewed_by').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            data = MenteeKYCDetailSerializer(kyc).data
            data['role'] = 'mentee'
            data['role_display'] = 'Eaglet (Mentee)'
        else:
            try:
                kyc = MentorKYC.objects.select_related('user', 'reviewed_by').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            data = MentorKYCDetailSerializer(kyc).data
            data['role'] = 'mentor'
            data['role_display'] = 'Eagle (Mentor)'

        return Response({
            'success': True,
            'data': data
        })

class AdminKYCStartReviewView(APIView):
    """
    Explicitly start reviewing a KYC application.

    Transitions a KYC application from 'submitted' to 'under_review' status.
    This is the proper POST-based replacement for the previous auto-transition
    that was incorrectly triggered on GET requests.

    POST /api/v1/admin/kyc/{kyc_id}/start-review/
    Body params:
        - role: 'mentor' or 'mentee' (required)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

        # Only transition from 'submitted' status
        if kyc.status != 'submitted':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatusTransition',
                    'message': (
                        f'Cannot start review: application status is '
                        f'"{kyc.get_status_display()}" (expected "Submitted").'
                    )
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        kyc.status = 'under_review'
        kyc.save(update_fields=['status'])

        logger.info(
            "KYC %s transitioned to under_review by admin %s",
            kyc_id, request.user.email,
        )

        return Response({
            'success': True,
            'data': {
                'id': str(kyc.id),
                'status': kyc.status,
                'status_display': kyc.get_status_display(),
                'message': 'Application is now under review.',
            }
        })

class AdminKYCApproveView(APIView):
    """
    Approve a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/approve/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - review_notes: Optional notes
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            serializer_class = MenteeKYCDetailSerializer
            role_display = 'Eaglet (Mentee)'
            feature_access = 'mentee features'
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

            serializer_class = MentorKYCDetailSerializer
            role_display = 'Eagle (Mentor)'
            feature_access = 'mentor features'

        # Check if can be approved
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot approve application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCApprovalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save review notes if provided
        review_notes = serializer.validated_data.get('review_notes', '')
        if review_notes:
            kyc.review_notes = review_notes

        # Approve the application
        kyc.approve(request.user)

        # Auto-create a Nest for mentors if they are approved
        if role == 'mentor':
            try:
                from apps.nests.services import NestService
                from apps.nests.models import Nest
                # Check if mentor already has a nest
                if not Nest.objects.filter(eagle=kyc.user).exists():
                    nest_name = f"{kyc.user.first_name}'s Nest" if kyc.user.first_name else f"Eagle {kyc.user.id}'s Nest"
                    industry_focus = kyc.current_occupation if getattr(kyc, 'current_occupation', None) else "General"
                    description = getattr(kyc, 'profile_description', "Welcome to my Nest! Let's grow together.")
                    if not description:
                        description = "Welcome to my Nest! Let's grow together."
                        
                    NestService.create_nest(kyc.user, {
                        "name": nest_name,
                        "description": description,
                        "industry_focus": industry_focus,
                        "privacy": "public",
                        "max_members": getattr(kyc, 'max_mentees', 10) or 10
                    })
                    logger.info(f"Auto-created Nest for newly approved mentor: {kyc.user.email}")
            except Exception as e:
                logger.error(f"Failed to auto-create Nest for mentor {kyc.user.email}: {e}")

        # Send approval notification email
        try:
            from ..tasks import send_profile_approved_email
            send_profile_approved_email.delay(str(kyc.user.id), role)
        except Exception as e:
            logger.error(f"Failed to queue approval email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role
        data['role_display'] = role_display

        return Response({
            'success': True,
            'data': data,
            'message': f'Application approved successfully. {kyc.user.full_name} can now access {feature_access}.'
        })

class AdminKYCRejectView(APIView):
    """
    Reject a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/reject/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - rejection_reason: Reason for rejection (required)
        - review_notes: Optional internal notes
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MenteeKYCDetailSerializer
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MentorKYCDetailSerializer

        # Check if can be rejected
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot reject application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCRejectionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        rejection_reason = serializer.validated_data['rejection_reason']
        review_notes = serializer.validated_data.get('review_notes', '')

        # Reject the application
        kyc.reject(request.user, rejection_reason)

        # Save internal review notes if provided
        if review_notes:
            kyc.review_notes = review_notes
            kyc.save(update_fields=['review_notes'])

        # Send rejection notification email
        try:
            from ..tasks import send_profile_rejected_email
            send_profile_rejected_email.delay(str(kyc.user.id), role, rejection_reason)
        except Exception as e:
            logger.error(f"Failed to queue rejection email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role

        return Response({
            'success': True,
            'data': data,
            'message': 'Application rejected. The applicant has been notified.'
        })

class AdminKYCRequestChangesView(APIView):
    """
    Request changes on a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/request-changes/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - review_notes: Required notes describing changes needed
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.select_related('user').get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MenteeKYCDetailSerializer
        else:
            try:
                kyc = MentorKYC.objects.select_related('user').get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            serializer_class = MentorKYCDetailSerializer

        # Check if changes can be requested
        if kyc.status not in ['submitted', 'under_review']:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidStatus',
                    'message': f'Cannot request changes for application with status "{kyc.get_status_display()}".'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = KYCRequestChangesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        review_notes = serializer.validated_data['review_notes']

        # Request changes
        kyc.request_changes(request.user, review_notes)

        # Send notification email
        try:
            from ..tasks import send_profile_changes_requested_email
            send_profile_changes_requested_email.delay(str(kyc.user.id), role, review_notes)
        except Exception as e:
            logger.error(f"Failed to queue changes requested email: {e}")

        data = serializer_class(kyc).data
        data['role'] = role

        return Response({
            'success': True,
            'data': data,
            'message': 'Changes requested. The applicant has been notified.'
        })

class AdminKYCNotesView(APIView):
    """
    Add internal notes to a KYC application (supports both mentor and mentee).

    POST /api/v1/admin/kyc/{kyc_id}/notes/
    Body params:
        - role: 'mentor' or 'mentee' (required)
        - note: The note content (required)
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, kyc_id):
        role = request.data.get('role', 'mentor')

        if role == 'mentee':
            try:
                kyc = MenteeKYC.objects.get(id=kyc_id)
            except MenteeKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentee KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                kyc = MentorKYC.objects.get(id=kyc_id)
            except MentorKYC.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'code': 404,
                        'type': 'NotFound',
                        'message': 'Mentor KYC application not found.'
                    }
                }, status=status.HTTP_404_NOT_FOUND)

        serializer = AdminInternalNoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        note = serializer.validated_data['note']
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M')
        author = request.user.full_name

        # Append note with timestamp and author
        new_note = f"[{timestamp}] {author}: {note}"

        if kyc.review_notes:
            kyc.review_notes = f"{kyc.review_notes}\n\n{new_note}"
        else:
            kyc.review_notes = new_note

        kyc.save(update_fields=['review_notes'])

        return Response({
            'success': True,
            'data': {
                'review_notes': kyc.review_notes,
                'role': role
            },
            'message': 'Note added successfully.'
        })

class AdminDashboardStatsView(APIView):
    """
    Get dashboard statistics for admin.

    GET /api/v1/admin/stats/
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Count
        from django.db.models.functions import TruncDate, TruncWeek
        from datetime import timedelta

        period = request.query_params.get('period', 'weekly')

        # User stats
        total_users = User.objects.filter(deleted_at__isnull=True).count()
        total_eagles = User.objects.filter(role='eagle', deleted_at__isnull=True).count()
        total_eaglets = User.objects.filter(role='eaglet', deleted_at__isnull=True).count()
        suspended_users = User.objects.filter(status='suspended', deleted_at__isnull=True).count()

        # Mentor KYC stats
        mentor_kyc_stats = MentorKYC.objects.aggregate(
            total=Count('id'),
            pending=Count('id', filter=models.Q(status__in=['submitted', 'under_review'])),
            approved=Count('id', filter=models.Q(status='approved')),
            rejected=Count('id', filter=models.Q(status='rejected')),
            requires_changes=Count('id', filter=models.Q(status='requires_changes')),
        )

        # Mentee KYC stats
        mentee_kyc_stats = MenteeKYC.objects.aggregate(
            total=Count('id'),
            pending=Count('id', filter=models.Q(status__in=['submitted', 'under_review'])),
            approved=Count('id', filter=models.Q(status='approved')),
            rejected=Count('id', filter=models.Q(status='rejected')),
            requires_changes=Count('id', filter=models.Q(status='requires_changes')),
        )

        # Combined pending KYC
        total_pending_kyc = (mentor_kyc_stats['pending'] or 0) + (mentee_kyc_stats['pending'] or 0)

        # Registration chart data based on period
        if period == 'monthly':
            # Last 30 days — aggregated by week (4 data points)
            month_ago = timezone.now() - timedelta(days=28)
            recent_registrations = list(
                User.objects.filter(
                    created_at__gte=month_ago,
                    deleted_at__isnull=True
                ).annotate(
                    week=TruncWeek('created_at')
                ).values('week').annotate(
                    count=Count('id')
                ).order_by('week')
            )
            # Convert week dates to ISO strings for JSON serialization
            for entry in recent_registrations:
                entry['date'] = entry.pop('week').isoformat()[:10]
        else:
            # Last 7 days — daily granularity
            week_ago = timezone.now() - timedelta(days=7)
            recent_registrations = list(
                User.objects.filter(
                    created_at__gte=week_ago,
                    deleted_at__isnull=True
                ).annotate(
                    date=TruncDate('created_at')
                ).values('date').annotate(
                    count=Count('id')
                ).order_by('date')
            )

        # Recent activity (last 10 events from various sources)
        recent_activity = []

        # Recent user registrations
        new_users = User.objects.filter(
            deleted_at__isnull=True
        ).order_by('-created_at')[:5]
        for u in new_users:
            recent_activity.append({
                'type': 'registration',
                'icon': 'person_add',
                'icon_bg': 'bg-emerald-100 text-emerald-600',
                'title': 'New user registered',
                'description': f'{u.full_name} joined as {u.get_role_display()}',
                'timestamp': u.created_at.isoformat(),
            })

        # Recent KYC submissions (mentors)
        recent_mentor_kyc = MentorKYC.objects.filter(
            submitted_at__isnull=False
        ).select_related('user').order_by('-submitted_at')[:3]
        for kyc in recent_mentor_kyc:
            recent_activity.append({
                'type': 'kyc_submission',
                'icon': 'verified_user',
                'icon_bg': 'bg-blue-100 text-blue-600',
                'title': 'KYC submitted',
                'description': f'{kyc.user.full_name} (Eagle) submitted KYC for review',
                'timestamp': kyc.submitted_at.isoformat(),
            })

        # Recent KYC submissions (mentees)
        recent_mentee_kyc = MenteeKYC.objects.filter(
            submitted_at__isnull=False
        ).select_related('user').order_by('-submitted_at')[:3]
        for kyc in recent_mentee_kyc:
            recent_activity.append({
                'type': 'kyc_submission',
                'icon': 'how_to_reg',
                'icon_bg': 'bg-purple-100 text-purple-600',
                'title': 'KYC submitted',
                'description': f'{kyc.user.full_name} (Eaglet) submitted KYC for review',
                'timestamp': kyc.submitted_at.isoformat(),
            })

        # Recent suspensions
        suspended = User.objects.filter(
            status='suspended',
            suspended_at__isnull=False
        ).order_by('-suspended_at')[:2]
        for u in suspended:
            recent_activity.append({
                'type': 'suspension',
                'icon': 'block',
                'icon_bg': 'bg-red-100 text-red-600',
                'title': 'User suspended',
                'description': f'{u.full_name} was suspended',
                'timestamp': u.suspended_at.isoformat(),
            })

        # Sort all activity by timestamp (most recent first)
        recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_activity = recent_activity[:10]

        return Response({
            'success': True,
            'data': {
                'users': {
                    'total': total_users,
                    'eagles': total_eagles,
                    'eaglets': total_eaglets,
                    'suspended': suspended_users,
                },
                'kyc': {
                    'mentor': mentor_kyc_stats,
                    'mentee': mentee_kyc_stats,
                    'total_pending': total_pending_kyc,
                },
                'recent_registrations': recent_registrations,
                'chart_period': period,
                'recent_activity': recent_activity,
            }
        })

class AdminUserListView(APIView):
    """
    List all platform users with filtering, search, and pagination.
    GET /api/v1/auth/admin/users/
    Query params:
        - role: eagle | eaglet | admin | all (default: all)
        - status: active | suspended | pending | inactive | all (default: all)
        - search: search by name or email
        - ordering: created_at | -created_at | full_name | -full_name (default: -created_at)
        - page: page number (default: 1)
        - per_page: items per page (default: 20, max: 100)
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from django.db.models import Q, Count, Sum, Value
        from django.db.models.functions import Coalesce
        from ..serializers import AdminUserSerializer

        role_filter = request.GET.get('role', 'all')
        status_filter = request.GET.get('status', 'all')
        search = request.GET.get('search', '').strip()
        ordering = request.GET.get('ordering', '-created_at')
        page = max(1, int(request.GET.get('page', 1)))
        per_page = min(max(1, int(request.GET.get('per_page', 20))), 100)

        # `select_related` on the KYC rows is load-bearing, not decorative:
        # the serializer exposes `User.avatar_url`, whose fallback chain reaches
        # for `mentor_kyc`/`mentee_kyc` (Phase 32-01). Without this, serializing
        # a page of N users issued N extra queries — measured at 63 queries for a
        # 20-row page, and this view allows per_page up to 100.
        # Mirrors apps/nests/views.py:107, which already selects `eagle__mentor_kyc`.
        # Deleted accounts are soft-deleted (deleted_at set, PII anonymized to
        # deleted_<uuid>@deleted.invalid) so historical records that reference
        # them stay intact. They must NOT appear in user management: the stats
        # cards above already exclude them, so without this the table showed a
        # ghost row and a count that disagreed with the cards.
        qs = User.objects.filter(deleted_at__isnull=True).select_related(
            'mentor_kyc', 'mentee_kyc'
        )

        # Annotate with activity metrics
        qs = qs.annotate(
            total_points=Coalesce(Sum('point_transactions__points'), Value(0)),
            nests_count=Count('owned_nests', distinct=True),
            eaglets_count=Count(
                'owned_nests__memberships',
                filter=Q(owned_nests__memberships__status='active'),
                distinct=True,
            ),
            content_created=Count('created_modules', distinct=True),
            content_completed=Count(
                'content_progress',
                filter=Q(content_progress__status='completed'),
                distinct=True,
            ),
            assignments_completed=Count(
                'assignment_submissions',
                filter=Q(assignment_submissions__status__in=['submitted', 'graded']),
                distinct=True,
            ),
        )

        if role_filter != 'all':
            qs = qs.filter(role=role_filter)

        if status_filter != 'all':
            qs = qs.filter(status=status_filter)

        if search:
            qs = qs.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )

        # Validate and apply ordering
        allowed_ordering = {'created_at', '-created_at', 'first_name', '-first_name', 'email', '-email', 'last_login', '-last_login'}
        if ordering not in allowed_ordering:
            ordering = '-created_at'
        qs = qs.order_by(ordering)

        total = qs.count()
        start = (page - 1) * per_page
        users = qs[start:start + per_page]

        serializer = AdminUserSerializer(users, many=True)

        return Response({
            'success': True,
            'data': {
                'users': serializer.data,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': max(1, (total + per_page - 1) // per_page),
                }
            }
        })

class AdminSuspendUserView(APIView):
    """
    Suspend an approved user (revoke platform access).
    POST /api/v1/auth/admin/users/<user_id>/suspend/
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'User not found.',
                }
            }, status=status.HTTP_404_NOT_FOUND)

        # Can't suspend admins
        if user.role == 'admin':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'Cannot suspend admin users.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Can't suspend already suspended users
        if user.status == 'suspended':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'User is already suspended.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate reason
        reason = request.data.get('reason', '').strip()
        if not reason or len(reason) < 10:
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'A suspension reason of at least 10 characters is required.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        user.suspend(request.user, reason)

        return Response({
            'success': True,
            'data': {
                'message': f'{user.full_name} has been suspended.',
                'user_id': str(user.id),
                'status': user.status,
                'suspended_at': user.suspended_at.isoformat(),
            }
        })

class AdminReactivateUserView(APIView):
    """
    Reactivate a suspended user.
    POST /api/v1/auth/admin/users/<user_id>/reactivate/
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 404,
                    'type': 'NotFound',
                    'message': 'User not found.',
                }
            }, status=status.HTTP_404_NOT_FOUND)

        if user.status != 'suspended':
            return Response({
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'ValidationError',
                    'message': 'User is not currently suspended.',
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        user.reactivate(request.user)

        return Response({
            'success': True,
            'data': {
                'message': f'{user.full_name} has been reactivated.',
                'user_id': str(user.id),
                'status': user.status,
            }
        })
