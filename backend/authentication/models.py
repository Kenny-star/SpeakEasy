from django.contrib.auth.models import AbstractBaseUser
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication
import jwt
from datetime import datetime, timezone as tz
import redis

class AccessTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Get the access token from the cookies
        access_token_str = request.COOKIES.get('access_token', None)

        if not access_token_str:
            raise AuthenticationFailed("No access token found. Please login.")
        
        try:
            # Decode the JWT access token to get the payload
            payload = jwt.decode(access_token_str, settings.SECRET_KEY, algorithms=[settings.SIMPLE_JWT['ALGORITHM']])

            user_id = payload.get('user_id')
            if not user_id:
                raise AuthenticationFailed('User ID not found in token')
            # Check for expiration in the payload
            exp_timestamp = payload.get('exp') 
            dt_object = datetime.fromtimestamp(exp_timestamp, tz=tz.utc)
            if dt_object < timezone.now():
                raise AuthenticationFailed('Access token has expired')
            
            # Check Redis cache for user
            redis_key = f'user_{user_id}'
            user = cache.get(redis_key)

            if not user:
                user = get_user_model().objects.filter(id=user_id).first()
                if not user:
                    raise AuthenticationFailed('User not found')
                # Cache the user object for subsequent requests
                cache.set(redis_key, user, timeout=1800)  # Cache for 30 min
            
            return (user, None)
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Access token has expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Invalid access token')
        except get_user_model().DoesNotExist:
            raise AuthenticationFailed('User not found')
        
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