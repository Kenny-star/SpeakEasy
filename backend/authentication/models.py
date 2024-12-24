from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist


class User(AbstractBaseUser):
    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=32, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()

    @classmethod
    def get_user_by_token(cls, token):
        try:
            # Retrieve the PasswordResetToken object by token
            reset_token = cls.objects.get(token=token)

            # Check if the token has expired
            if reset_token.is_expired():
                raise ValueError("Token has expired")

            # Return the associated user
            return reset_token.user
        
        except ObjectDoesNotExist:
            raise ValueError("Invalid token")
        except ValueError as e:
            raise ValueError(str(e))
        
    def is_expired(self):
        return timezone.now() > self.expired_at

    def __str__(self):
        return f"Password reset token for {self.user.email}"


class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Password history for {self.user.email} created at {self.created_at}"

class RefreshToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()


    def is_expired(self):
        return timezone.now() > self.expired_at

    def __str__(self):
        return f"Refresh token for {self.user.email}"