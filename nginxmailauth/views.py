from django.conf import settings
from django.db.utils import DatabaseError
from django.http import HttpResponseForbidden
from django.shortcuts import render_to_response
from django.template.context import RequestContext

from models import MailUser
from utils import get_fail_response, get_success_response
from forms import PasswordChangeForm


def authenticate(request):
    username = request.META.get('HTTP_AUTH_USER')
    password = request.META.get('HTTP_AUTH_PASS')
    protocol = request.META.get('HTTP_AUTH_PROTOCOL')
    shared_secret = request.META.get('HTTP_X_NGX_AUTH_KEY')

    if None in [username, password, protocol, shared_secret] or\
    shared_secret != settings.NGX_AUTH_KEY or \
    request.META['REMOTE_ADDR'] not in settings.ALLOWED_NGINX_IPS:
        return HttpResponseForbidden()

    try:
        mail_user = MailUser.objects.active().select_related().get(internal_username=username)
    except (MailUser.DoesNotExist, MailUser.MultipleObjectsReturned, DatabaseError):
        return get_fail_response()

    if mail_user.authenticate(password):
        return get_success_response(mail_user.external_username,
                            getattr(mail_user.server, protocol),
                            getattr(mail_user.server, protocol+'_port'),
                            mail_user.external_password or None)
    else:
        return get_fail_response()


def change_password(request):
    if request.POST:
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            mail_user = form.cleaned_data['user']
            mail_user.change_password(form.cleaned_data['new_password'])
            return render_to_response('mailauth/password_change.html', {'message': "Password changed successfully"},
                                      context_instance=RequestContext(request))
    else:
        form = PasswordChangeForm()
    return render_to_response('mailauth/password_change.html', {'form': form},
                               context_instance=RequestContext(request))