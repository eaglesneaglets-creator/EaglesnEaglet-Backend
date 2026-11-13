"""Convert legacy PUBLIC KYC documents to private (authenticated) delivery.

Government IDs, CVs and recommendation letters used to be uploaded as public
Cloudinary assets and stored as their ``secure_url``: anyone with the link
could open them. New uploads are private (see core/private_docs.py). This
command converts the old ones in place:

    python manage.py privatize_kyc_documents --dry-run   # report only
    python manage.py privatize_kyc_documents             # apply

For each row it switches the Cloudinary asset's delivery type to
``authenticated`` (no re-upload, CDN copy invalidated) and replaces the stored
URL with a private reference. Safe to re-run: rows already holding a private
reference are skipped. Values that are not Cloudinary upload URLs are reported
and left untouched.
"""
from django.core.management.base import BaseCommand

from apps.users.models import MenteeKYC, MentorKYC
from core.private_docs import is_private_reference, parse_public_url, privatize_public_asset

TARGETS = (
    (MentorKYC, ("government_id", "recommendation_letter", "cv")),
    (MenteeKYC, ("cv",)),
)


class Command(BaseCommand):
    help = "Switch legacy public KYC documents (IDs, CVs, recommendation letters) to private delivery."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Report without changing anything.")

    def handle(self, *args, dry_run=False, **options):
        totals = {"converted": 0, "already": 0, "unrecognised": 0, "failed": 0}
        for model, fields in TARGETS:
            for field in fields:
                qs = model.objects.exclude(**{f"{field}__isnull": True}).exclude(**{field: ""})
                for pk, value in qs.values_list("pk", field).iterator():
                    value = str(value)
                    if is_private_reference(value):
                        totals["already"] += 1
                        continue
                    if parse_public_url(value) is None:
                        totals["unrecognised"] += 1
                        self.stdout.write(self.style.WARNING(
                            f"{model.__name__}.{field} pk={pk}: not a Cloudinary upload URL — left as is"
                        ))
                        continue
                    if dry_run:
                        totals["converted"] += 1
                        continue
                    try:
                        ref = privatize_public_asset(value)
                    except Exception as exc:  # Cloudinary API error: report, keep going
                        totals["failed"] += 1
                        self.stderr.write(f"{model.__name__}.{field} pk={pk}: conversion failed: {exc}")
                        continue
                    # Compare-and-swap so a concurrent re-upload is never overwritten.
                    updated = model.objects.filter(pk=pk, **{field: value}).update(**{field: ref})
                    totals["converted" if updated else "failed"] += 1

        verb = "would be converted" if dry_run else "converted"
        self.stdout.write(self.style.SUCCESS(
            f"{totals['converted']} document(s) {verb}, {totals['already']} already private, "
            f"{totals['unrecognised']} unrecognised, {totals['failed']} failed."
        ))
