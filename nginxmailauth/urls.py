from django.conf.urls.defaults import patterns, include, url
from views import authenticate, change_password

urlpatterns = patterns('',
    url(r'auth$', authenticate, name='mailauth_nginx_authenticate'),
    url(r'change_password$', change_password, name="mailauth_change_password")
)
