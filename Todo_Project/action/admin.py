from django.contrib import admin
from .models import Action


class TodoAdmin(admin.ModelAdmin):
    readonly_fields = ('created',)

admin.site.register(Action, TodoAdmin)
