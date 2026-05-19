"""Django admin registrations for the nests app."""

from django.contrib import admin

from .models_program import (
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
    ProgramObjective,
    ProgramObjectiveRule,
)


class ProgramObjectiveRuleInline(admin.TabularInline):
    model = ProgramObjectiveRule
    extra = 0
    fields = ("rule_type", "target", "config")


@admin.register(ProgramObjective)
class ProgramObjectiveAdmin(admin.ModelAdmin):
    list_display = ("title", "program", "order")
    list_filter = ("program__nest",)
    search_fields = ("title", "program__name")
    inlines = (ProgramObjectiveRuleInline,)


@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = ("name", "nest", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("name", "nest__name")
    readonly_fields = ("activated_at", "archived_at", "created_at", "updated_at")
    autocomplete_fields = ()  # Nest admin not registered yet; can be added later.


@admin.register(ProgramEnrollment)
class ProgramEnrollmentAdmin(admin.ModelAdmin):
    list_display = ("mentee", "program", "status", "requested_at", "started_at", "ended_at")
    list_filter = ("status", "program__nest")
    search_fields = ("mentee__email", "program__name")
    readonly_fields = (
        "requested_at", "started_at", "ended_at",
        "rules_snapshot", "created_at", "updated_at",
    )


@admin.register(ProgramExitRequest)
class ProgramExitRequestAdmin(admin.ModelAdmin):
    list_display = ("enrollment", "requested_by", "status", "decided_by", "decided_at")
    list_filter = ("status",)
    search_fields = ("enrollment__mentee__email",)
    readonly_fields = ("decided_at", "created_at", "updated_at")
