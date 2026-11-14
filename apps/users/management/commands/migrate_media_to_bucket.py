"""Copy Cloudinary media into the S3 bucket and repoint the database.

    python manage.py migrate_media_to_bucket --dry-run     # report only, writes nothing
    python manage.py migrate_media_to_bucket               # copy + update rows
    python manage.py migrate_media_to_bucket --limit 20    # small first batch

What it does
------------
Scans every text/URL/file/JSON column of every model for Cloudinary URLs
(``https://res.cloudinary.com/...``) and private references
(``cld-private:...``). For each one it downloads the file, uploads it to the
bucket and rewrites the stored value:

* public asset   -> stable media URL (``{BACKEND_URL}/api/v1/media/...``)
* KYC document   -> ``s3-private:<key>`` (bucket ``private/`` prefix), whether
                    it was already private on Cloudinary or a legacy public URL

Safety
------
* Nothing is deleted from Cloudinary. Roll back by unsetting the S3_* vars.
* Resumable and idempotent: keys are derived from the Cloudinary path, objects
  already in the bucket are not re-uploaded, converted rows no longer match.
* Each row update is compare-and-swap on the old value, so an edit made while
  the command runs is never overwritten.
* A failed download leaves that value untouched and is listed at the end.
"""
from __future__ import annotations

import json
import mimetypes
import re
from collections import Counter

import requests
from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import models
from django.db.models import TextField
from django.db.models.functions import Cast

from core import object_storage, private_docs

CLOUDINARY_URL_RE = re.compile(r"https?://res\.cloudinary\.com/[^\s\"'<>\\)]+")
CLD_PRIVATE_RE = re.compile(r"cld-private:[^\s\"'<>\\)]+")
#: (app_label.ModelName, field) pairs that hold identity documents: these go
#: to the private prefix even when the stored value is a public URL.
PRIVATE_FIELDS = {
    ("users.MentorKYC", "government_id"),
    ("users.MentorKYC", "recommendation_letter"),
    ("users.MentorKYC", "cv"),
    ("users.MenteeKYC", "cv"),
}
SKIP_APPS = {"sessions", "admin", "contenttypes", "auth", "django_celery_beat", "django_celery_results"}
SCAN_TYPES = (models.CharField, models.TextField, models.FileField, models.JSONField)


class Command(BaseCommand):
    help = "Copy Cloudinary media into the S3 bucket and repoint database values."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Report what would move; write nothing.")
        parser.add_argument("--limit", type=int, default=0, help="Stop after N files (0 = all).")
        parser.add_argument("--check-sources", action="store_true",
                            help="With --dry-run: also request each source file to confirm it is reachable and total the bytes.")
        parser.add_argument("--inventory", action="store_true",
                            help="Read-only: count non-empty values per file/URL column, grouped by host "
                                 "(values themselves are never printed), then exit.")

    def _inventory(self):
        """Per-column breakdown of what is stored, by host. Read-only."""
        from urllib.parse import urlsplit

        url_fields = (models.URLField, models.FileField)
        for model, field in self._targets():
            name = field.name
            if not (isinstance(field, url_fields) or name.endswith(("_url", "image", "picture", "avatar"))):
                continue
            qs = model._default_manager.exclude(**{f"{name}__isnull": True}).exclude(**{name: ""})
            hosts = Counter()
            for value in qs.values_list(name, flat=True).iterator():
                v = str(value)
                if v.startswith("cld-private:"):
                    hosts["cld-private ref"] += 1
                elif v.startswith("s3-private:"):
                    hosts["s3-private ref"] += 1
                elif "://" in v:
                    hosts[urlsplit(v).hostname or "?"] += 1
                else:
                    hosts["relative storage name (no host)"] += 1
            if hosts:
                summary = ", ".join(f"{h}: {n}" for h, n in hosts.most_common())
                self.stdout.write(f"  {model._meta.app_label}.{model.__name__}.{name}: {summary}")

    # ── helpers ──────────────────────────────────────────────────────────

    def _targets(self):
        for model in apps.get_models():
            if model._meta.app_label in SKIP_APPS or model._meta.proxy or not model._meta.managed:
                continue
            for field in model._meta.concrete_fields:
                if isinstance(field, SCAN_TYPES) and not field.primary_key:
                    yield model, field

    def _rows(self, model, field):
        """(pk, raw stored text) for rows whose column mentions Cloudinary."""
        qs = model._default_manager.annotate(_raw=Cast(field.name, TextField()))
        qs = qs.filter(models.Q(_raw__contains="res.cloudinary.com") | models.Q(_raw__contains="cld-private:"))
        return qs.values_list("pk", "_raw").iterator()

    @staticmethod
    def _key_for(source: str, private: bool) -> str | None:
        """Deterministic bucket key from the Cloudinary identity of ``source``."""
        if source.startswith("cld-private:"):
            ref = private_docs.parse_reference(source)
            if not ref:
                return None
            rtype, fmt, public_id = ref
            path = public_id if (rtype == "raw" or not fmt) else f"{public_id}.{fmt}"
        else:
            parsed = private_docs.parse_public_url(source)
            if not parsed:
                return None
            rtype, fmt, public_id = parsed
            path = public_id if (rtype == "raw" or not fmt) else f"{public_id}.{fmt}"
        path = "/".join(object_storage.safe_filename(p) for p in path.split("/") if p)
        return (object_storage.PRIVATE_PREFIX if private else object_storage.PUBLIC_PREFIX) + path

    @staticmethod
    def _download_url(source: str) -> str:
        if source.startswith("cld-private:"):
            return private_docs.signed_document_url(source, ttl=900)
        return source

    def _copy(self, source: str, key: str) -> int:
        """Copy one file into the bucket (skip if already there). Returns bytes copied."""
        if object_storage.exists(key):
            return 0
        resp = requests.get(self._download_url(source), timeout=120)
        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "").split(";")[0].strip()
        if not ctype or ctype == "application/octet-stream":
            ctype = mimetypes.guess_type(key)[0] or "application/octet-stream"
        object_storage.put_bytes(key, resp.content, ctype)
        return len(resp.content)

    # ── main ───────────────────────────────────────────────────────────

    def handle(self, *args, dry_run=False, limit=0, check_sources=False, inventory=False, **options):
        if inventory:
            self._inventory()
            return
        if not object_storage.is_configured():
            raise CommandError(
                "The S3 bucket is not configured. Connect the Railway bucket to this "
                "service (AWS_* variables) or set S3_BUCKET, S3_ENDPOINT, "
                "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY."
            )
        if not dry_run:
            # Fail fast on bad credentials before touching any row.
            object_storage.exists(object_storage.PUBLIC_PREFIX + "__connection_check__")

        per_field = Counter()
        done = {}            # source -> replacement (also dedupes shared files)
        failures = []
        stats = Counter()

        for model, field in self._targets():
            label = f"{model._meta.app_label}.{model.__name__}"
            private = (label, field.name) in PRIVATE_FIELDS
            for pk, raw in self._rows(model, field):
                sources = set(CLOUDINARY_URL_RE.findall(raw)) | set(CLD_PRIVATE_RE.findall(raw))
                new_raw = raw
                for source in sources:
                    is_private = private or source.startswith("cld-private:")
                    if source not in done:
                        if limit and stats["files"] >= limit:
                            continue
                        key = self._key_for(source, is_private)
                        if key is None:
                            failures.append((label, field.name, pk, source, "unrecognised Cloudinary value"))
                            done[source] = None
                            continue
                        stats["files"] += 1
                        try:
                            if dry_run:
                                if check_sources:
                                    r = requests.get(self._download_url(source), timeout=60, stream=True)
                                    r.raise_for_status()
                                    stats["bytes"] += int(r.headers.get("Content-Length") or 0)
                                    r.close()
                            else:
                                stats["bytes"] += self._copy(source, key)
                        except Exception as exc:
                            failures.append((label, field.name, pk, source, str(exc)[:160]))
                            done[source] = None
                            continue
                        done[source] = (
                            f"{private_docs.S3_PRIVATE_PREFIX}{key}" if is_private else object_storage.media_url(key)
                        )
                    if done.get(source):
                        new_raw = new_raw.replace(source, done[source])

                if new_raw == raw:
                    continue
                max_len = getattr(field, "max_length", None)
                if max_len and len(new_raw) > max_len:
                    failures.append((label, field.name, pk, raw, f"new value is {len(new_raw)} chars; column allows {max_len}"))
                    continue
                per_field[f"{label}.{field.name}"] += 1
                if dry_run:
                    continue
                value = json.loads(new_raw) if isinstance(field, models.JSONField) else new_raw
                # Compare-and-swap on the raw stored text.
                updated = (
                    model._default_manager
                    .annotate(_raw=Cast(field.name, TextField()))
                    .filter(pk=pk, _raw=raw)
                    .update(**{field.name: value})
                )
                stats["rows" if updated else "rows_changed_concurrently"] += 1

        verb = "would be" if dry_run else "were"
        self.stdout.write("")
        for name, n in sorted(per_field.items()):
            self.stdout.write(f"  {name}: {n} row(s)")
        mb = stats["bytes"] / (1024 * 1024)
        self.stdout.write(self.style.SUCCESS(
            f"{stats['files']} file(s) {verb} copied"
            + (f" ({mb:.1f} MB)" if stats["bytes"] else "")
            + f"; {sum(per_field.values())} row(s) {verb} repointed."
        ))
        if stats["rows_changed_concurrently"]:
            self.stdout.write(self.style.WARNING(
                f"{stats['rows_changed_concurrently']} row(s) changed while running and were skipped; re-run to pick them up."
            ))
        if failures:
            self.stdout.write(self.style.WARNING(f"{len(failures)} value(s) could not be migrated:"))
            for label, fname, pk, source, why in failures[:50]:
                self.stdout.write(f"  {label}.{fname} pk={pk}: {source[:90]} -> {why}")
        if limit and stats["files"] >= limit:
            self.stdout.write(f"Stopped at --limit {limit}. Run again to continue.")
