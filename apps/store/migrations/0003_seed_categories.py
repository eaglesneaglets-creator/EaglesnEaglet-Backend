"""
Seed default store categories.

Categories chosen for a mentorship/community e-commerce platform:
- Apparel (branded clothing, uniforms)
- Books & Resources (educational materials)
- Accessories (caps, bags, wristbands)
- Stationery (notebooks, pens, planners)
- Digital Products (e-books, courses, templates)
- Food & Beverages (event catering items, snacks)
- Health & Wellness (self-care, fitness items)
- Gift Cards & Vouchers
- Event Tickets (conferences, workshops)
- Merchandise (branded items, memorabilia)
"""

from django.db import migrations
from django.utils.text import slugify


CATEGORIES = [
    ("Apparel", "Branded clothing, t-shirts, hoodies, and uniforms."),
    ("Books & Resources", "Educational books, workbooks, and learning materials."),
    ("Accessories", "Caps, bags, wristbands, lanyards, and more."),
    ("Stationery", "Notebooks, pens, planners, and office supplies."),
    ("Digital Products", "E-books, online courses, templates, and digital downloads."),
    ("Food & Beverages", "Snacks, drinks, and event catering items."),
    ("Health & Wellness", "Self-care products, fitness gear, and wellness items."),
    ("Gift Cards & Vouchers", "Redeemable gift cards and vouchers for the store."),
    ("Event Tickets", "Tickets for conferences, workshops, and community events."),
    ("Merchandise", "Branded memorabilia, collectibles, and limited-edition items."),
]


def seed_categories(apps, schema_editor):
    Category = apps.get_model("store", "Category")
    for name, description in CATEGORIES:
        slug = slugify(name)
        if not Category.objects.filter(slug=slug).exists():
            Category.objects.create(
                name=name,
                slug=slug,
                description=description,
                is_active=True,
            )


def remove_categories(apps, schema_editor):
    Category = apps.get_model("store", "Category")
    slugs = [slugify(name) for name, _ in CATEGORIES]
    Category.objects.filter(slug__in=slugs).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("store", "0002_fix_model_constraints"),
    ]

    operations = [
        migrations.RunPython(seed_categories, remove_categories),
    ]