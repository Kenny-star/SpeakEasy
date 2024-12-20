from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from authentication.models import PasswordHistory

@receiver(pre_save, sender=User)
def store_password_history(sender, instance, **kwargs):
    # If the password is changing, store the old password
    if instance.pk:  # Ensure it's not a new user
        old_user = User.objects.get(pk=instance.pk)
        if old_user.password != instance.password:  # Check if password has changed
            # Save old password hash to PasswordHistory
            PasswordHistory.objects.create(user=instance, password_hash=old_user.password)
