"""Create the media bucket if it does not exist (LOCAL DEVELOPMENT ONLY).

On Railway the bucket is provisioned by the platform; this command is for the
local S3 stand-in in docker-compose, where a fresh volume has no bucket yet.
It is a no-op when object storage is not configured.
"""
import time

from django.core.management.base import BaseCommand

from core import object_storage


class Command(BaseCommand):
    help = "Create the S3 media bucket if missing (local dev)."

    def handle(self, *args, **options):
        if not object_storage.is_configured():
            self.stdout.write("Object storage not configured; nothing to do.")
            return
        from botocore.exceptions import ClientError, EndpointConnectionError

        name = object_storage.bucket()
        client = object_storage.client()
        for attempt in range(20):
            try:
                client.head_bucket(Bucket=name)
                self.stdout.write(f"Bucket {name!r} exists.")
                return
            except EndpointConnectionError:
                time.sleep(1.5)  # store still starting
            except ClientError:
                try:
                    client.create_bucket(Bucket=name)
                    self.stdout.write(self.style.SUCCESS(f"Created bucket {name!r}."))
                    return
                except ClientError as exc:
                    self.stderr.write(f"Could not create bucket {name!r}: {exc}")
                    return
        self.stderr.write("Object store did not become reachable; continuing without a bucket.")
