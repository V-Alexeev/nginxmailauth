from django import forms

from models import MailUser

class PasswordChangeForm(forms.Form):
    username = forms.CharField(max_length=50)
    old_password = forms.CharField(max_length=50, widget=forms.PasswordInput)
    new_password = forms.CharField(max_length=50, widget=forms.PasswordInput)
    confirm_new_password = forms.CharField(max_length=50, widget=forms.PasswordInput)

    def clean(self):
        try:
            mail_user = MailUser.objects.select_related().get(internal_username=self.cleaned_data['username'])
        except (MailUser.DoesNotExist, MailUser.MultipleObjectsReturned):
            raise forms.ValidationError("Incorrect username or old password")

        if (not mail_user.disabled) and mail_user.authenticate(self.cleaned_data['old_password']):
            self.cleaned_data['user'] = mail_user
        else:
            raise forms.ValidationError("Incorrect username or old password")

        if self.cleaned_data['new_password'] != self.cleaned_data['confirm_new_password']:
            raise forms.ValidationError("New password and confirmation don't match")

        return self.cleaned_data