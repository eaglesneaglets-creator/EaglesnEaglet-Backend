"""
Management command to seed the store with sample products.
"""

from decimal import Decimal

from django.core.management.base import BaseCommand
from django.utils.text import slugify

from apps.store.models import Category, Product, ProductImage


class Command(BaseCommand):
    help = "Seed the store with sample products"

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear all products, images, and categories before seeding",
        )

    def handle(self, *args, **options):
        if options["clear"]:
            self.stdout.write("Clearing existing store data...")
            ProductImage.objects.all().delete()
            Product.objects.all().delete()
            Category.objects.all().delete()
            self.stdout.write("  Store data cleared.")

        CATEGORIES = [
            "Merchandise",
            "Digital Resources",
            "Books & Guides",
            "Accessories",
            "Equipment",
        ]

        PRODUCTS = [
            {"name": "Eagles Cap",                   "category": "Merchandise",       "price": Decimal("45.00"),  "stock": 50},
            {"name": "Eagles Hoodie",                "category": "Merchandise",       "price": Decimal("150.00"), "stock": 25},
            {"name": "Mentorship Mastery eBook",     "category": "Digital Resources", "price": Decimal("25.00"),  "stock": 999},
            {"name": "Goal Setting Toolkit (PDF)",   "category": "Digital Resources", "price": Decimal("15.00"),  "stock": 999},
            {"name": "The Eagle Mindset Book",       "category": "Books & Guides",    "price": Decimal("55.00"),  "stock": 30},
            {"name": "Eaglet Study Planner",         "category": "Books & Guides",    "price": Decimal("30.00"),  "stock": 40},
            {"name": "Eagles Branded Notebook",      "category": "Accessories",       "price": Decimal("20.00"),  "stock": 60},
            {"name": "Eagles Water Bottle",          "category": "Accessories",       "price": Decimal("35.00"),  "stock": 45},
            {"name": "Study Desk Lamp",              "category": "Equipment",         "price": Decimal("120.00"), "stock": 20},
            {"name": "Noise-Cancelling Earbuds",     "category": "Equipment",         "price": Decimal("200.00"), "stock": 15},
        ]

        # Seed categories
        self.stdout.write("Seeding categories...")
        category_map: dict[str, Category] = {}
        for cat_name in CATEGORIES:
            cat_slug = slugify(cat_name)
            category, _ = Category.objects.get_or_create(
                slug=cat_slug,
                defaults={"name": cat_name, "is_active": True},
            )
            category_map[cat_name] = category

        # Seed products
        self.stdout.write("Seeding products...")
        created_count = 0
        existing_count = 0

        for p_data in PRODUCTS:
            product_slug = slugify(p_data["name"])
            category = category_map[p_data["category"]]

            product, created = Product.objects.get_or_create(
                slug=product_slug,
                defaults={
                    "name": p_data["name"],
                    "category": category,
                    "price": p_data["price"],
                    "stock_quantity": p_data["stock"],
                    "status": Product.Status.PUBLISHED,
                },
            )

            # Idempotent image creation: one primary image per product
            image_url = f"https://picsum.photos/seed/{product_slug}/600/600"
            img, img_created = ProductImage.objects.get_or_create(
                product=product,
                is_primary=True,
                defaults={
                    "image_url": image_url,
                    "display_order": 0,
                },
            )
            # If image already existed but URL changed (re-seed after clear), update it
            if not img_created and img.image_url != image_url:
                img.image_url = image_url
                img.display_order = 0
                img.save(update_fields=["image_url", "display_order"])

            if created:
                created_count += 1
            else:
                existing_count += 1

            self.stdout.write(
                f"  [ok] {product.name} ({'created' if created else 'already exists'})"
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Seed complete: {created_count} created, {existing_count} already existed."
            )
        )
