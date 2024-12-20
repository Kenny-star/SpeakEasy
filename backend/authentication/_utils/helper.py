from datetime import timedelta
from django.conf import settings
from django.http import JsonResponse
from authentication.models import User

def create_cookie(response, token_type, token_value, max_age):
    response.set_cookie(
        token_type, token_value,
        max_age=max_age,
        secure=settings.SECURE_COOKIE,  # Only for HTTPS cookies
        httponly=settings.HTTP_ONLY,  # Prevent access to the cookie via JavaScript
        samesite=settings.SAME_SITE,  # Prevent cross-site request forgery
    )

def authenticate_login(email=None, password=None):
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None