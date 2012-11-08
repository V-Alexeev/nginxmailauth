from django.contrib import admin
from django.shortcuts import render_to_response
from django.template.context import RequestContext

from models import MailServer, MailUser
from utils import generate_password


class MailUserAdmin(admin.ModelAdmin):
    list_display = ('internal_username', 'external_username', 'server', 'disabled')
    list_filter = ('server', 'auth_method')
    search_fields = ('internal_username', 'external_username')
    actions = ['randomize_password', 'disable_accounts', 'enable_accounts']

    def disable_accounts(self, request, queryset):
        queryset.update(disabled=True)

    def enable_accounts(self, request, queryset):
        queryset.update(disabled=True)

    def randomize_password(self, request, queryset):
        passwords = {}
        for mailuser in queryset:
            password = generate_password(length=8)
            mailuser.change_password(password)
            passwords.update({mailuser.internal_username: password})
        return render_to_response('mailauth/admin/password_change_result.html', {'passwords': passwords},
                context_instance=RequestContext(request))
    randomize_password.short_description = "Generate a random password for selected accounts"


class MailServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'imap', 'pop3', 'smtp')


admin.site.register(MailUser, MailUserAdmin)
admin.site.register(MailServer, MailServerAdmin)