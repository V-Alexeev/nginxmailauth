from django.db import models

from methods import AuthMethodMetaclass

AUTHENTICATION_CHOICES = [(unicode(klass), unicode(klass)) for klass in AuthMethodMetaclass.register \
                                        if not klass.hidden]


class MailUser(models.Model):
    internal_username = models.CharField("Internal username", max_length=50, db_index=True, unique=True)
    internal_password = models.CharField("Internal password", max_length=50, blank=True, default='',
                                     help_text="This may be not used at all, i.e. if using Kerberos auth")
    external_username = models.CharField("External username", max_length=100, blank=True, default='',
                                         help_text="If left blank, it is assumed to be the same as the internal")
    external_password = models.CharField("External password", max_length=50,
                                     help_text="This is the user's password, used at the external service only")
    server = models.ForeignKey("MailServer", related_name="users")
    auth_method = models.CharField("Authentication method", max_length=100, choices=AUTHENTICATION_CHOICES)

    @property
    def auth_class(self):
        for klass in AuthMethodMetaclass.register:
            if unicode(klass) == self.auth_method:
                return klass
        raise KeyError('Authentication class %s not found!' % self.auth_method)

    def authenticate(self, password):
        return self.auth_class.authenticate(self, password)

    def change_password(self, new_password):
        self.internal_password = self.auth_class.get_password(self, new_password)
        self.save()

    def __unicode__(self):
        return self.external_username


class MailServer(models.Model):
    name = models.CharField("Name", max_length=200, help_text="Human-readable name of the server")
    imap = models.CharField("IMAP server", max_length=500, help_text="Domain name or IP address of IMAP server")
    imap_port = models.SmallIntegerField("IMAP server port", default=143)
    pop3 = models.CharField("POP3 server", max_length=500, help_text="Domain name or IP address of POP3 server")
    pop3_port = models.SmallIntegerField("POP3 server port", default=110)
    smtp = models.CharField("SMTP server", max_length=500, help_text="Domain name or IP address of SMTP server")
    smtp_port = models.SmallIntegerField("SMTP server port", default=25)

    def __unicode__(self):
        return self.name