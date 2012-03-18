import sys
if sys.version_info < (2, 5):
    from md5 import md5
else:
    from hashlib import md5

class AuthMethodMetaclass(type):
    register = []

    def __new__(cls, what, bases=None, dict=None):
        if 'hidden' not in dict: dict['hidden'] = False
        klass = type.__new__(cls, what, bases, dict)
        AuthMethodMetaclass.register += [klass]
        return klass

    def __unicode__(cls):
        return cls.__name__


class BaseAuthenticationMethod(object):
    hidden = True     # If hidden is set to True, the authentication method is not shown in admin interface

    @classmethod
    def get_password(cls, mail_user, password):
        """
        Returns the value of password to be used with this authentication method
        (e.g. MD5 hash of the original password)

        If the method returns None, it means that this authentication method doesn't
        use passwords stored in the app's database (e.g. uses external Kerberos auth)
        """
        return None

    @classmethod
    def authenticate(cls, mail_user, password):
        """Should return True if login is successful, False otherwise"""
        processed_password = cls.get_password(mail_user, password)
        return (processed_password is not None) and (processed_password == mail_user.internal_password)

    __metaclass__ = AuthMethodMetaclass


class MD5NameHostnamePwdAuthenticationMethod(BaseAuthenticationMethod):
    @classmethod
    def get_password(cls, mail_user, password):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        digest_base = "%s:%s" % (mail_user.internal_username.lower().replace('@', ':').encode(), password)
        return md5(digest_base).hexdigest()


class MD5AuthenticationMethod(BaseAuthenticationMethod):
    @classmethod
    def get_password(cls, mail_user, password):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        return md5(password).hexdigest()


class PlaintextAuthenticationMethod(BaseAuthenticationMethod):
    @classmethod
    def get_password(cls, mail_user, password):
        return password