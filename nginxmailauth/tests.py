from django.test import TestCase
from django.test.utils import override_settings
from django.db.utils import IntegrityError

from models import MailServer, MailUser
import methods

CORRECT_INTERNAL_PASSWORD = u"pass123"
INTERNAL_USERNAME = u"a_username@example.com"
EXTERNAL_USERNAME=u"a_real_username@example.com"
EXTERNAL_PASSWORD=u"aHARDpassword"
CORRECT_NGX_KEY = u"some_nginx_preshared_secret_key"
NEW_PASS = "somenewpass"

def setUpModule():
    global mail_server
    mail_server = MailServer(name="test server", imap="imap-test.v-alexeev.ru",
        imap_port=341, pop3="pop-test.v-alexeev.ru", pop3_port=1110,
        smtp="smtp-test.v-alexeev.ru", smtp_port=52)
    mail_server.save()

class AuthMethodsTest(TestCase):
    def setUp(self):
        self.user = MailUser(internal_username=INTERNAL_USERNAME,
                             internal_password=CORRECT_INTERNAL_PASSWORD,
                             external_username=EXTERNAL_USERNAME,
                             external_password=EXTERNAL_PASSWORD,
                             server=mail_server,
                             auth_method="noSuchMethod")
        self.user.save()

    def test_no_such_method(self):
        self.assertRaises(KeyError, getattr, self.user, "auth_class")
        self.assertRaises(KeyError, self.user.authenticate, CORRECT_INTERNAL_PASSWORD)
        self.assertRaises(KeyError, self.user.change_password, "some pass")

    def test_base_method(self):
        self.user.auth_method = "BaseAuthenticationMethod"
        self.user.save()
        self.assertIs(self.user.auth_class, methods.BaseAuthenticationMethod)
        self.assertFalse(self.user.authenticate(CORRECT_INTERNAL_PASSWORD))
        # The password cannot be Null
        self.assertRaises(IntegrityError, self.user.change_password, u"Some new password")

    def test_plain_method(self):
        self.user.auth_method = "PlaintextAuthenticationMethod"
        self.user.save()
        self.assertIs(self.user.auth_class, methods.PlaintextAuthenticationMethod)
        self.assertTrue(self.user.authenticate(CORRECT_INTERNAL_PASSWORD))
        self.user.change_password(CORRECT_INTERNAL_PASSWORD)
        self.assertEqual(self.user.internal_password, CORRECT_INTERNAL_PASSWORD)

    def test_md5_method(self):
        self.user.auth_method = "MD5AuthenticationMethod"
        self.user.save()
        self.assertIs(self.user.auth_class, methods.MD5AuthenticationMethod)
        md5_pwd = u'32250170a0dca92d53ec9624f336ca24'
        self.user.internal_password = md5_pwd
        self.user.save()
        self.assertTrue(self.user.authenticate(CORRECT_INTERNAL_PASSWORD))
        self.user.change_password(CORRECT_INTERNAL_PASSWORD)
        self.assertEqual(self.user.internal_password, md5_pwd)

    def test_md5_name_hostname_pwd_method(self):
        self.user.auth_method = "MD5NameHostnamePwdAuthenticationMethod"
        self.user.save()
        self.assertIs(self.user.auth_class, methods.MD5NameHostnamePwdAuthenticationMethod)
        md5_name_hostname_pwd = u'99128b41e0484eef1628332c235f0b01'
        self.user.internal_password = md5_name_hostname_pwd
        self.user.save()
        self.assertTrue(self.user.authenticate(CORRECT_INTERNAL_PASSWORD))
        self.user.change_password(CORRECT_INTERNAL_PASSWORD)
        self.assertEqual(self.user.internal_password, md5_name_hostname_pwd)

    def tearDown(self):
        self.user.delete()


@override_settings(NGX_AUTH_KEY=CORRECT_NGX_KEY, ALLOWED_NGINX_IPS=("1.1.1.1", "2.2.2.2"),
            ROOT_URLCONF="nginxmailauth.urls")
class NginxInteractionTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.user = MailUser(internal_username=INTERNAL_USERNAME,
            internal_password=CORRECT_INTERNAL_PASSWORD,
            external_username=EXTERNAL_USERNAME,
            external_password=EXTERNAL_PASSWORD,
            server=mail_server,
            auth_method="PlaintextAuthenticationMethod")
        cls.user.save()

    def test_nginx_auth_illegal_headers(self):
        response = self.client.get('/auth')
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/auth', HTTP_AUTH_USER=INTERNAL_USERNAME,
                                        HTTP_AUTH_PASS=CORRECT_INTERNAL_PASSWORD,
                                        HTTP_AUTH_PROTOCOL="imap",
                                        REMOTE_ADDR="1.1.1.1",
                                        HTTP_X_NGX_AUTH_KEY="incorrect key")
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/auth', HTTP_AUTH_USER=INTERNAL_USERNAME,
                                        HTTP_AUTH_PASS=CORRECT_INTERNAL_PASSWORD,
                                        HTTP_AUTH_PROTOCOL="imap",
                                        REMOTE_ADDR="3.3.3.3",
                                        HTTP_X_NGX_AUTH_KEY=CORRECT_NGX_KEY)
        self.assertEqual(response.status_code, 403)

    def test_nginx_successful_auth(self):
        response = self.client.get('/auth', HTTP_AUTH_USER=INTERNAL_USERNAME,
                                        HTTP_AUTH_PASS=CORRECT_INTERNAL_PASSWORD,
                                        HTTP_AUTH_PROTOCOL="imap",
                                        REMOTE_ADDR="2.2.2.2",
                                        HTTP_X_NGX_AUTH_KEY=CORRECT_NGX_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Auth-Status"], "OK")
        self.assertEqual(response["Auth-Port"], "341")
        self.assertEqual(response["Auth-Server"], "1.2.3.4") # I just set this A-record at my DNS, so it could be broken someday
        self.assertEqual(response["Auth-User"], EXTERNAL_USERNAME)
        self.assertEqual(response["Auth-Pass"], EXTERNAL_PASSWORD)

    def test_nginx_wrong_username_or_password(self):
        response = self.client.get('/auth', HTTP_AUTH_USER=INTERNAL_USERNAME,
                                        HTTP_AUTH_PASS="incorrect pass",
                                        HTTP_AUTH_PROTOCOL="imap",
                                        REMOTE_ADDR="2.2.2.2",
                                        HTTP_X_NGX_AUTH_KEY=CORRECT_NGX_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Auth-Status"], "Invalid login or password")
        self.assertEqual(response["Auth-Wait"], "3")
        response = self.client.get('/auth', HTTP_AUTH_USER="NOSUCHUSER",
            HTTP_AUTH_PASS=CORRECT_INTERNAL_PASSWORD,
            HTTP_AUTH_PROTOCOL="imap",
            REMOTE_ADDR="2.2.2.2",
            HTTP_X_NGX_AUTH_KEY=CORRECT_NGX_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Auth-Status"], "Invalid login or password")
        self.assertEqual(response["Auth-Wait"], "3")

    @classmethod
    def tearDownClass(cls):
        cls.user.delete()


@override_settings(ROOT_URLCONF="nginxmailauth.urls")
class UserInteractionsTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.user = MailUser(internal_username=INTERNAL_USERNAME,
            internal_password=CORRECT_INTERNAL_PASSWORD,
            external_username=EXTERNAL_USERNAME,
            external_password=EXTERNAL_PASSWORD,
            server=mail_server,
            auth_method="PlaintextAuthenticationMethod")
        cls.user.save()

    def test_change_password_wrong_old_username_pass(self):
        response = self.client.post("/change_password", data={
            "username": INTERNAL_USERNAME,
            "old_password": "someincorrectpass",
            "new_password": NEW_PASS,
            "confirm_new_password": NEW_PASS
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", None, "Incorrect username or old password")
        response = self.client.post("/change_password", data={
            "username": "NOSUCHUSER",
            "old_password": CORRECT_INTERNAL_PASSWORD,
            "new_password": NEW_PASS,
            "confirm_new_password": NEW_PASS
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", None, "Incorrect username or old password")

    def test_change_password_wrong_confirmation_pass(self):
        response = self.client.post("/change_password", data={
            "username": INTERNAL_USERNAME,
            "old_password": CORRECT_INTERNAL_PASSWORD,
            "new_password": NEW_PASS,
            "confirm_new_password": "anothernewpass"
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", None, "New password and confirmation don't match")

    def test_change_password_successful(self):
        response = self.client.post("/change_password", data={
            "username": INTERNAL_USERNAME,
            "old_password": CORRECT_INTERNAL_PASSWORD,
            "new_password": NEW_PASS,
            "confirm_new_password": NEW_PASS
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Password changed successfully")
        user = MailUser.objects.get(internal_username=INTERNAL_USERNAME)
        self.assertEqual(user.internal_password, NEW_PASS)

    @classmethod
    def tearDownClass(cls):
        cls.user.delete()