"""
Content Services

Business logic for learning content management, progress tracking,
and assignment submission/grading.
"""

import logging

from django.db import transaction
from django.db.models import Avg, Count, Q, QuerySet
from django.utils import timezone
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from apps.nests.models import Nest, NestMembership

from .models import (
    ContentModule,
    ContentItem,
    Assignment,
    ContentProgress,
    AssignmentSubmission,
    ModuleAssignment,
    ModuleQuestion,
    ModuleAssignmentAttempt,
)

logger = logging.getLogger(__name__)


class ContentService:
    """Handles learning content CRUD and uploads."""

    # ------------------------------------------------------------------
    # Module CRUD
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def create_module(user, nest_id: str, data: dict) -> ContentModule:
        """Create a content module in a Nest (Eagle) or globally (Admin)."""
        nest = None
        if nest_id:
            try:
                nest = Nest.objects.get(pk=nest_id)
            except Nest.DoesNotExist:
                raise NotFound("Nest not found.")
            
            if user.role != 'admin' and nest.eagle_id != user.id:
                raise PermissionDenied("Only the Nest owner or an Admin can create content modules in this nest.")
        else:
            if user.role != 'admin':
                raise PermissionDenied("Only admins can create global content modules.")

        thumbnail = data.pop('thumbnail', None)
        if thumbnail:
            from core.storage import upload_to_cloudinary
            upload_result = upload_to_cloudinary(thumbnail, file_type='content_images')
            data['thumbnail_url'] = upload_result.get('secure_url')

        module = ContentModule.objects.create(
            nest=nest, created_by=user, **data
        )
        logger.info("Module created: %s in %s", module.title, nest.name if nest else "Global")
        return module

    @staticmethod
    def update_module(user, module_id: str, data: dict) -> ContentModule:
        """Update a content module (owner or admin only)."""
        try:
            module = ContentModule.objects.select_related("nest").get(pk=module_id)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can update modules.")

        thumbnail = data.pop('thumbnail', None)
        if thumbnail:
            from core.storage import upload_to_cloudinary
            upload_result = upload_to_cloudinary(thumbnail, file_type='content_images')
            data['thumbnail_url'] = upload_result.get('secure_url')

        for field, value in data.items():
            setattr(module, field, value)
        module.save()
        logger.info("Module updated: %s", module.title)
        return module

    @staticmethod
    def delete_module(user, module_id: str) -> None:
        """Delete a content module (owner or admin only)."""
        try:
            module = ContentModule.objects.select_related("nest").get(pk=module_id)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can delete modules.")

        module_title = module.title
        module.delete()
        logger.info("Module deleted: %s", module_title)

    @staticmethod
    def publish_module(user, module_id: str) -> ContentModule:
        """Publish a module, making it visible to Eaglets."""
        try:
            module = ContentModule.objects.select_related("nest").get(pk=module_id)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can publish modules.")

        if module.items.count() == 0:
            raise ValidationError(
                {"module": "Add at least one content item before publishing."}
            )

        module.is_published = True
        module.save(update_fields=["is_published"])
        logger.info("Module published: %s", module.title)
        return module

    @staticmethod
    def get_nest_modules(nest_id: str, user=None, created_by_id: str = None):
        """Return modules for a Nest (plus globals) or by creator."""
        if created_by_id:
            qs = ContentModule.objects.filter(created_by_id=created_by_id)
        elif nest_id:
            qs = ContentModule.objects.filter(
                Q(nest_id=nest_id) | Q(nest__isnull=True)
            ).select_related("created_by", "nest").prefetch_related("items")
        else:
            qs = ContentModule.objects.filter(nest__isnull=True).select_related("created_by").prefetch_related("items")

        if user and user.role == "eaglet":
            qs = qs.filter(is_published=True)

        return qs.select_related("created_by", "nest").prefetch_related("items")

    # ------------------------------------------------------------------
    # Content Item CRUD
    # ------------------------------------------------------------------

    @staticmethod
    def add_content_item(user, module_id: str, data: dict) -> ContentItem:
        """Add a content item to a module (Eagle/Admin)."""
        try:
            module = ContentModule.objects.select_related("nest").get(pk=module_id)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can add content items.")

        file = data.pop('file', None)
        thumbnail = data.pop('thumbnail', None)
        
        if file:
            from core.storage import upload_to_cloudinary, get_video_thumbnail, get_pdf_thumbnail
            content_type = data.get('content_type', 'reading')
            file_type = 'videos' if content_type == 'video' else 'misc'
            
            try:
                # Upload the main file
                upload_result = upload_to_cloudinary(file, file_type=file_type)
                data['file_url'] = upload_result.get('secure_url')
                data['file_size'] = upload_result.get('bytes')
                public_id = upload_result.get('public_id')

                # Auto-generate thumbnail if not manually provided
                if not thumbnail and public_id:
                    if content_type == 'video':
                        data['thumbnail_url'] = get_video_thumbnail(public_id)
                    elif content_type == 'document' and str(file).lower().endswith('.pdf'):
                        data['thumbnail_url'] = get_pdf_thumbnail(public_id)
            except Exception as e:
                logger.error(f"Failed to upload file to Cloudinary: {e}")
                raise ValidationError({"file": "Failed to upload file. Please try again."})

        # Manual thumbnail upload
        if thumbnail:
            from core.storage import upload_to_cloudinary
            thumb_result = upload_to_cloudinary(thumbnail, file_type='content_images')
            data['thumbnail_url'] = thumb_result.get('secure_url')

        item = ContentItem.objects.create(module=module, **data)
        
        # Propagate thumbnail to module if it's currently empty
        if not module.thumbnail_url and item.thumbnail_url:
            module.thumbnail_url = item.thumbnail_url
            module.save(update_fields=['thumbnail_url'])

        logger.info("Content item added: %s to %s", item.title, module.title)
        return item

    @staticmethod
    def update_content_item(user, item_id: str, data: dict) -> ContentItem:
        """Update a content item (module owner or admin only)."""
        try:
            item = ContentItem.objects.select_related("module__nest").get(pk=item_id)
        except ContentItem.DoesNotExist:
            raise NotFound("Content item not found.")

        module = item.module
        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can update content items.")

        file = data.pop('file', None)
        thumbnail = data.pop('thumbnail', None)

        if file:
            from core.storage import upload_to_cloudinary, get_video_thumbnail, get_pdf_thumbnail
            content_type = data.get('content_type', item.content_type)
            file_type = 'videos' if content_type == 'video' else 'misc'
            
            try:
                upload_result = upload_to_cloudinary(file, file_type=file_type)
                data['file_url'] = upload_result.get('secure_url')
                data['file_size'] = upload_result.get('bytes')
                public_id = upload_result.get('public_id')

                # Auto-generate thumbnail if not manually provided and file changed
                if not thumbnail and public_id:
                    if content_type == 'video':
                        data['thumbnail_url'] = get_video_thumbnail(public_id)
                    elif content_type == 'document' and str(file).lower().endswith('.pdf'):
                        data['thumbnail_url'] = get_pdf_thumbnail(public_id)
            except Exception as e:
                logger.error(f"Failed to upload file to Cloudinary: {e}")
                raise ValidationError({"file": "Failed to upload file. Please try again."})

        # Manual thumbnail upload
        if thumbnail:
            from core.storage import upload_to_cloudinary
            thumb_result = upload_to_cloudinary(thumbnail, file_type='content_images')
            data['thumbnail_url'] = thumb_result.get('secure_url')

        for field, value in data.items():
            setattr(item, field, value)
        item.save()

        # Propagate thumbnail to module if it's currently empty
        if not module.thumbnail_url and item.thumbnail_url:
            module.thumbnail_url = item.thumbnail_url
            module.save(update_fields=['thumbnail_url'])

        logger.info("Content item updated: %s", item.title)
        return item

    @staticmethod
    def delete_content_item(user, item_id: str) -> None:
        """Delete a content item (module owner or admin only)."""
        try:
            item = ContentItem.objects.select_related("module__nest").get(pk=item_id)
        except ContentItem.DoesNotExist:
            raise NotFound("Content item not found.")

        module = item.module
        if user.role != 'admin' and (not module.nest or module.nest.eagle_id != user.id):
            raise PermissionDenied("Only the Nest owner or an Admin can delete content items.")

        item_title = item.title
        item.delete()
        logger.info("Content item deleted: %s from %s", item_title, module.title)

    @staticmethod
    def get_module_items(module_id: str):
        """Return content items in a module."""
        return ContentItem.objects.filter(module_id=module_id).order_by("order")

    # ------------------------------------------------------------------
    # Assignment CRUD
    # ------------------------------------------------------------------

    @staticmethod
    def create_assignment(eagle, module_id: str, data: dict) -> Assignment:
        """Create an assignment in a module (Eagle only). Kept for backward compat."""
        try:
            module = ContentModule.objects.select_related("nest__eagle").get(pk=module_id)
        except ContentModule.DoesNotExist:
            raise NotFound("Module not found.")

        if module.nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can create assignments.")

        assignment = Assignment.objects.create(module=module, **data)
        logger.info("Assignment created: %s in %s", assignment.title, module.title)

        # Notify all active nest members
        ContentService._notify_nest_of_assignment(assignment, module.nest, eagle)
        return assignment

    @staticmethod
    @transaction.atomic
    def create_standalone_assignment(eagle, nest_id: str, data: dict, file=None) -> Assignment:
        """Create a nest-wide standalone assignment (Eagle only)."""
        try:
            from apps.nests.models import Nest
            nest = Nest.objects.get(pk=nest_id)
        except Exception:
            raise NotFound("Nest not found.")

        if eagle.role != "admin" and nest.eagle_id != eagle.id:
            raise PermissionDenied("Only the Nest owner can create assignments.")

        file_url = data.pop("file_url", None)
        if file:
            from core.storage import upload_to_cloudinary
            result = upload_to_cloudinary(file, file_type="misc")
            file_url = result.get("secure_url")

        assignment = Assignment.objects.create(
            assignment_type="standalone",
            nest=nest,
            created_by=eagle,
            file_url=file_url or "",
            **data,
        )
        logger.info("Standalone assignment created: %s in nest %s", assignment.title, nest.name)

        # Notify all active nest members
        ContentService._notify_nest_of_assignment(assignment, nest, eagle)
        return assignment

    @staticmethod
    def _notify_nest_of_assignment(assignment: Assignment, nest, eagle) -> None:
        """Bulk-notify all active nest members of a new assignment and bust their dashboard caches."""
        from apps.notifications.models import Notification
        from apps.analytics.services import AnalyticsService

        members = list(
            NestMembership.objects.filter(
                nest=nest, status="active"
            ).select_related("user")
        )

        notifications = [
            Notification(
                recipient=membership.user,
                notification_type=Notification.NotificationType.CONTENT_PUBLISHED,
                title="New Assignment",
                message=f"{eagle.full_name} has posted a new assignment: '{assignment.title}'.",
                action_url="/eaglet/assignments/",
            )
            for membership in members
        ]
        if notifications:
            Notification.objects.bulk_create(notifications)
            # Bust each eaglet's dashboard cache so recent content appears immediately
            for membership in members:
                AnalyticsService.clear_dashboard_cache(
                    str(membership.user.id), membership.user.role
                )
            logger.info(
                "Notified %d members of assignment '%s' in nest '%s'",
                len(notifications), assignment.title, nest.name,
            )


class ProgressService:
    """Handles content progress tracking and assignment submissions."""

    # ------------------------------------------------------------------
    # Content Progress
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def update_progress(
        user, content_item_id: str, progress_percentage: float,
        watch_duration_seconds: int = 0,
    ) -> ContentProgress:
        """Update a user's progress on a content item."""
        try:
            item = ContentItem.objects.select_related("module__nest").get(
                pk=content_item_id
            )
        except ContentItem.DoesNotExist:
            raise NotFound("Content item not found.")

        # Verify membership
        if not NestMembership.objects.filter(
            nest=item.module.nest, user=user, status="active"
        ).exists():
            raise PermissionDenied("You must be a Nest member to track progress.")

        progress, created = ContentProgress.objects.get_or_create(
            user=user, content_item=item,
            defaults={"started_at": timezone.now()},
        )
        
        # Serialize access by locking the row for this transaction
        progress = ContentProgress.objects.select_for_update().get(id=progress.id)

        # Fraud prevention: progress can only increase
        if progress.status == "completed":
            return progress

        progress.progress_percentage = max(
            progress.progress_percentage, min(progress_percentage, 100.0)
        )
        progress.watch_duration_seconds = max(
            progress.watch_duration_seconds, watch_duration_seconds
        )

        # Fraud prevention: videos require minimum watch time (50% of duration)
        if (
            item.content_type == "video"
            and progress.progress_percentage >= 100.0
            and item.duration_minutes > 0
        ):
            min_seconds = int(item.duration_minutes * 60 * 0.5)
            if progress.watch_duration_seconds < min_seconds:
                logger.warning(
                    "Fraud blocked: user=%s item=%s watched %ds of required %ds",
                    user.email, item.id, progress.watch_duration_seconds, min_seconds,
                )
                progress.progress_percentage = min(
                    progress.progress_percentage, 99.0
                )

        if progress.progress_percentage >= 100.0 and progress.status != "completed":
            progress.status = ContentProgress.Status.COMPLETED
            progress.completed_at = timezone.now()
            # Points awarded via post_save signal in apps.points.signals
        elif progress.progress_percentage > 0 and progress.status != "completed":
            progress.status = ContentProgress.Status.IN_PROGRESS
            if not progress.started_at:
                progress.started_at = timezone.now()

        progress.save()
        return progress

    @staticmethod
    def get_user_progress(user, nest_id: str = None):
        """Get a user's content progress, optionally filtered by nest."""
        qs = ContentProgress.objects.filter(user=user).select_related(
            "content_item__module__nest"
        )
        if nest_id:
            qs = qs.filter(content_item__module__nest_id=nest_id)
        return qs

    @staticmethod
    def get_user_progress_summary(user):
        """Dashboard summary: total, in-progress, completed counts scoped to user's Nests."""
        from .models import ContentItem, Assignment, ContentModule, AssignmentSubmission
        
        # Get nests the user is a member of
        nest_ids = NestMembership.objects.filter(
            user=user, status="active"
        ).values_list("nest_id", flat=True)
        
        # Base querysets scoped to user's nests + global
        visible_modules = ContentModule.objects.filter(
            Q(nest_id__in=nest_ids) | Q(nest__isnull=True),
            is_published=True
        )
        visible_items = ContentItem.objects.filter(module__in=visible_modules)
        visible_assignments = Assignment.objects.filter(module__in=visible_modules)
        
        qs = ContentProgress.objects.filter(user=user, content_item__in=visible_items)
        
        # Breakdown calculations
        total_videos = visible_items.filter(content_type="video").count()
        completed_videos = qs.filter(status="completed", content_item__content_type="video").count()
        
        total_assignments = visible_assignments.count()
        
        # FIX: Only distinct assignments with at least one submission
        completed_assignment_ids = set(AssignmentSubmission.objects.filter(
            user=user, assignment__in=visible_assignments
        ).values_list("assignment_id", flat=True).distinct())
        
        completed_assignments = len(completed_assignment_ids)

        total_modules = visible_modules.count()
        
        # Calculate modules completed (all required items done AND any associated assignments submitted)
        modules_completed = 0
        for module in visible_modules:
            module_assignments = module.assignments.all()
            has_assignment = module_assignments.exists()
            
            # Basic item completion
            item_completion = ProgressService.get_module_completion_percentage(user, module.id)
            
            if item_completion >= 100.0:
                if has_assignment:
                    # Must also have submitted at least one assignment in this module
                    asg_ids = set(module_assignments.values_list("id", flat=True))
                    if asg_ids.intersection(completed_assignment_ids):
                        modules_completed += 1
                else:
                    modules_completed += 1
                
        avg_prog = qs.aggregate(avg=Avg("progress_percentage"))["avg"] or 0

        return {
            "total_items": visible_items.count(),
            "completed": qs.filter(status="completed").count(),
            "in_progress": qs.filter(status="in_progress").count(),
            "average_progress": avg_prog,
            "overall_progress": avg_prog,
            "modules_completed": modules_completed,
            "total_modules": total_modules,
            "breakdown": {
                "videos": {"completed": completed_videos, "total": total_videos},
                "assignments": {"completed": completed_assignments, "total": total_assignments},
            }
        }


    @staticmethod
    def get_module_completion_percentage(user, module_id: str) -> float:
        """Calculate user's overall completion percentage for a module."""
        required_items = ContentItem.objects.filter(
            module_id=module_id, is_required=True
        ).count()

        if required_items == 0:
            return 100.0

        completed = ContentProgress.objects.filter(
            user=user,
            content_item__module_id=module_id,
            content_item__is_required=True,
            status="completed",
        ).count()

        return round((completed / required_items) * 100, 1)

    @staticmethod
    def check_resource_gate(user, module) -> bool:
        """
        Returns True if the user has ≥50% progress on ALL required items in
        the module. Used to gate quiz access.
        """
        required_items = module.items.filter(is_required=True)
        if not required_items.exists():
            return True
        completed_count = ContentProgress.objects.filter(
            user=user,
            content_item__in=required_items,
            progress_percentage__gte=50,
        ).count()
        return completed_count >= required_items.count()

    @staticmethod
    def check_module_completion(user, module) -> bool:
        """
        Awards module_complete points if ALL required items are ≥50% done
        AND the module quiz (if any) has been passed. Idempotent via source_id.
        """
        if not ProgressService.check_resource_gate(user, module):
            return False

        # If a quiz exists, it must have been passed
        if hasattr(module, "quiz"):
            passed = module.quiz.attempts.filter(user=user, passed=True).exists()
            if not passed:
                return False

        from apps.points.services import PointService
        PointService.award_points(
            user=user,
            activity_type="module_complete",
            source_id=str(module.id),
            nest=module.nest,
        )
        return True

    @staticmethod
    def get_bulk_module_progress(user, module_ids: list) -> dict:
        """
        Calculate progress for multiple modules in one batch.
        Returns a mapping of module_id -> {progress_percentage, status}
        """
        if not module_ids:
            return {}

        # Normalise to strings so dict/set lookups match DRF-serialised UUIDs.
        # Django ORM .values()/.values_list() returns uuid.UUID objects which are
        # NOT equal to str UUIDs, causing silent cache misses on every lookup.
        module_ids = [str(mid) for mid in module_ids]

        # 1. Get required item counts per module
        required_counts = ContentItem.objects.filter(
            module_id__in=module_ids, is_required=True
        ).values("module_id").annotate(total=Count("id"))

        required_map = {str(item["module_id"]): item["total"] for item in required_counts}

        # 2. Get completed item counts per module for this user
        completed_counts = ContentProgress.objects.filter(
            user=user,
            content_item__module_id__in=module_ids,
            content_item__is_required=True,
            status="completed"
        ).values("content_item__module_id").annotate(total=Count("id"))

        completed_map = {str(item["content_item__module_id"]): item["total"] for item in completed_counts}

        # 3. Get assignment completion info (for modules with assignments)
        any_submission_ids = {
            str(mid) for mid in AssignmentSubmission.objects.filter(
                user=user, assignment__module_id__in=module_ids
            ).values_list("assignment__module_id", flat=True).distinct()
        }

        # 4. Check for any progress records (to distinguish not_started vs in_progress)
        any_progress_ids = {
            str(mid) for mid in ContentProgress.objects.filter(
                user=user, content_item__module_id__in=module_ids
            ).values_list("content_item__module_id", flat=True).distinct()
        }

        # 5. Pre-batch assignment existence check to avoid N+1 queries
        modules_with_assignments = {
            str(mid) for mid in Assignment.objects.filter(module_id__in=module_ids)
            .values_list("module_id", flat=True).distinct()
        }

        # 6. Pre-batch quiz existence and passing-attempt checks
        modules_with_quiz = {
            str(mid) for mid in ModuleAssignment.objects.filter(module_id__in=module_ids)
            .values_list("module_id", flat=True).distinct()
        }
        modules_with_passing_quiz = {
            str(mid) for mid in ModuleAssignmentAttempt.objects.filter(
                assignment__module_id__in=module_ids,
                user=user,
                passed=True,
            ).values_list("assignment__module_id", flat=True).distinct()
        }

        results = {}
        for mid in module_ids:
            total_req = required_map.get(mid, 0)
            has_assignment = mid in modules_with_assignments
            is_submitted = mid in any_submission_ids
            has_quiz = mid in modules_with_quiz
            quiz_passed = mid in modules_with_passing_quiz

            # Calculate item-based percentage
            if total_req == 0:
                # No required content items — completion depends on quiz or assignment.
                if has_quiz:
                    percentage = 100.0 if quiz_passed else 0.0
                elif has_assignment:
                    percentage = 100.0 if is_submitted else 0.0
                else:
                    percentage = 0.0
            else:
                done = completed_map.get(mid, 0)
                percentage = round((done / total_req) * 100, 1)

            # Determine status — module is only "completed" when content is done
            # AND any required quiz has been passed AND any required assignment submitted.
            status = "not_started"

            if percentage >= 100.0:
                if has_quiz and not quiz_passed:
                    status = "in_progress"
                    percentage = 99.0
                elif has_assignment and not is_submitted:
                    status = "in_progress"
                    percentage = 99.0
                else:
                    status = "completed"
            elif percentage > 0 or is_submitted or quiz_passed or mid in any_progress_ids:
                status = "in_progress"
                
            results[mid] = {
                "progress_percentage": percentage,
                "status": status
            }
            
        return results


    # ------------------------------------------------------------------
    # Assignment Submission
    # ------------------------------------------------------------------

    @staticmethod
    @transaction.atomic
    def submit_assignment(user, assignment_id: str, data: dict) -> AssignmentSubmission:
        """Submit work for an assignment."""
        try:
            assignment = Assignment.objects.select_related(
                "nest", "module__nest"
            ).get(pk=assignment_id)
        except Assignment.DoesNotExist:
            raise NotFound("Assignment not found.")

        # Standalone assignments use assignment.nest; legacy module-based use module.nest
        assignment_nest = assignment.nest or (
            assignment.module.nest if assignment.module else None
        )
        if not assignment_nest:
            raise ValidationError({"assignment": "This assignment is not associated with a nest."})

        # Verify membership
        if not NestMembership.objects.filter(
            nest=assignment_nest, user=user, status="active"
        ).exists():
            raise PermissionDenied("You must be a Nest member to submit assignments.")

        # Check submission limit
        existing_count = AssignmentSubmission.objects.filter(
            assignment=assignment, user=user
        ).count()
        if existing_count >= assignment.max_submissions:
            raise ValidationError(
                {"assignment": f"Maximum of {assignment.max_submissions} submissions allowed."}
            )

        # Check due date
        if assignment.due_date and timezone.now() > assignment.due_date:
            raise ValidationError({"assignment": "This assignment is past due."})

        submission = AssignmentSubmission.objects.create(
            assignment=assignment, user=user, **data
        )
        logger.info("Assignment submitted: %s by %s", assignment.title, user.email)
        return submission

    @staticmethod
    def grade_submission(
        eagle, submission_id: str, grade: str, feedback: str
    ) -> AssignmentSubmission:
        """Grade an assignment submission (Eagle only)."""
        try:
            submission = AssignmentSubmission.objects.select_related(
                "assignment__nest", "assignment__module__nest"
            ).get(pk=submission_id)
        except AssignmentSubmission.DoesNotExist:
            raise NotFound("Submission not found.")

        # Standalone assignments have a direct nest FK; module-linked ones use module.nest
        nest = submission.assignment.nest or (
            submission.assignment.module.nest if submission.assignment.module else None
        )
        if not nest or (nest.eagle_id != eagle.id and eagle.role != "admin"):
            raise PermissionDenied("Only the Nest owner can grade submissions.")

        submission.grade = grade
        submission.feedback = feedback
        submission.status = AssignmentSubmission.Status.GRADED
        submission.graded_by = eagle
        submission.save(update_fields=["grade", "feedback", "status", "graded_by"])

        logger.info("Submission graded: %s", submission_id)

        # Award gamification points to the eaglet whose work was graded
        if submission.user.role == "eaglet":
            from apps.points.services import PointService
            award_nest = submission.assignment.nest or (
                submission.assignment.module.nest if submission.assignment.module else None
            )
            PointService.award_points(
                submission.user,
                "assignment_graded",
                source_id=str(submission.id),
                nest=award_nest,
            )

        return submission
    @staticmethod
    def get_mentor_submissions(
        mentor, nest_id: str = None, submission_status: str = None
    ) -> QuerySet:
        """Fetch all submissions for assignments in a mentor's nests."""

        qs = AssignmentSubmission.objects.filter(
            assignment__nest__eagle=mentor
        ).select_related("assignment__nest", "user")

        if nest_id:
            qs = qs.filter(assignment__nest_id=nest_id)

        if submission_status:
            qs = qs.filter(status=submission_status)

        return qs


class ModuleQuizService:
    """Handles MCQ + descriptive quiz creation and attempt grading."""

    @staticmethod
    @transaction.atomic
    def create_quiz(module, validated_data: dict, questions_data: list) -> ModuleAssignment:
        """Eagle creates (or replaces) the quiz for a module."""
        quiz, _ = ModuleAssignment.objects.update_or_create(
            module=module,
            defaults={
                "title": validated_data["title"],
                "pass_score": validated_data.get("pass_score", 60),
                "max_attempts": validated_data.get("max_attempts", 3),
                "points_value": validated_data.get("points_value", 50),
            },
        )
        quiz.questions.all().delete()
        for i, q in enumerate(questions_data):
            ModuleQuestion.objects.create(assignment=quiz, order=i, **q)
        logger.info("Quiz created/updated: %s for module %s", quiz.title, module.title)
        return quiz

    @staticmethod
    def get_quiz_for_eagle(module_id: str) -> ModuleAssignment:
        """Returns the quiz with correct answers (Eagle view)."""
        try:
            return ModuleAssignment.objects.prefetch_related("questions").get(
                module_id=module_id
            )
        except ModuleAssignment.DoesNotExist:
            raise NotFound("This module has no quiz yet.")

    @staticmethod
    def get_quiz_for_eaglet(module_id: str, user) -> tuple:
        """Returns (quiz, attempts_used). Strips correct_option from questions."""
        try:
            quiz = ModuleAssignment.objects.prefetch_related("questions").get(
                module_id=module_id
            )
        except ModuleAssignment.DoesNotExist:
            raise NotFound("This module has no quiz.")
        attempts_used = quiz.attempts.filter(user=user).count()
        return quiz, attempts_used

    @staticmethod
    @transaction.atomic
    def submit_attempt(quiz_id: int, user, answers: dict) -> dict:
        """
        Auto-grades MCQ questions, records descriptive answers.
        Returns {score, passed, attempt_number, correct_count, total_mcq}.
        Raises ValidationError if max_attempts exceeded or resource gate not cleared.
        """
        try:
            quiz = (
                ModuleAssignment.objects
                .prefetch_related("questions")
                .select_related("module")
                .select_for_update()
                .get(id=quiz_id)
            )
        except ModuleAssignment.DoesNotExist:
            raise NotFound("Quiz not found.")

        if not ProgressService.check_resource_gate(user, quiz.module):
            raise ValidationError(
                "Complete at least 50% of all required resources before taking the quiz."
            )

        attempt_count = quiz.attempts.filter(user=user).count()
        if attempt_count >= quiz.max_attempts:
            raise ValidationError(
                f"Maximum {quiz.max_attempts} attempts reached."
            )

        all_questions = list(quiz.questions.all())
        mcq_questions = [q for q in all_questions if q.question_type == "mcq"]
        correct = sum(
            1
            for q in mcq_questions
            if str(q.id) in answers and answers[str(q.id)] == q.correct_option
        )
        score = int((correct / len(mcq_questions)) * 100) if mcq_questions else 100
        passed = score >= quiz.pass_score

        attempt = ModuleAssignmentAttempt.objects.create(
            assignment=quiz,
            user=user,
            answers=answers,
            score=score,
            passed=passed,
            attempt_number=attempt_count + 1,
            completed_at=timezone.now(),
        )

        if passed:
            ProgressService.check_module_completion(user, quiz.module)

        logger.info(
            "Quiz attempt: user=%s quiz=%s attempt=#%d score=%d passed=%s",
            user.email, quiz_id, attempt.attempt_number, score, passed,
        )

        return {
            "score": score,
            "passed": passed,
            "attempt_number": attempt.attempt_number,
            "correct_count": correct,
            "total_mcq": len(mcq_questions),
            "attempts_remaining": quiz.max_attempts - attempt.attempt_number,
        }
