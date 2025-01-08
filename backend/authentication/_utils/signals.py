from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.signals import user_logged_in
from django.conf import settings
from django.utils.timezone import now
from datetime import timedelta
from authentication.models import PasswordHistory
from authentication._utils._tokens import generate_verification_token
from authentication._utils.email import send_verification_email_async

duration = settings.EMAIL_TOKEN_CONFIRMATION_EXPIRY

@receiver(pre_save, sender=User)
def store_password_history(sender, instance, **kwargs):
    # If the password is changing, store the old password
    if instance.pk:  # Ensure it's not a new user
        old_user = User.objects.get(pk=instance.pk)
        if old_user.password != instance.password:  # Check if password has changed
            # Save old password hash to PasswordHistory
            PasswordHistory.objects.create(user=instance, password_hash=old_user.password)

            PasswordHistory.objects.filter(user=instance).order_by('-created_at')[settings.SIMPLE_JWT['MAX_USER_PASSWORD_HISTORY_LENGTH']:].delete()

