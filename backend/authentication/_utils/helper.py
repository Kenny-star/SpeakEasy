from datetime import timedelta
from django.conf import settings
from django.http import JsonResponse
from rest_framework.exceptions import AuthenticationFailed

def create_cookie(response, token_type, token_value, max_age):
    response.set_cookie(
        token_type, token_value,
        max_age=max_age,
        secure=settings.SECURE_COOKIE,  # Only for HTTPS cookies
        httponly=settings.HTTP_ONLY,  # Prevent access to the cookie via JavaScript
        samesite=settings.SAME_SITE,  # Prevent cross-site request forgery
    )

def authenticate_login(email=None, password=None):
        from django.contrib.auth import get_user_model  # Lazy import to avoid circular import

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

def extract_access_token_from_header(request):

    auth_header = request.headers.get('Authorization', None)

    if not auth_header:
        raise AuthenticationFailed("Authorization header missing.")

    parts = auth_header.split()

    if parts[0].lower() != 'bearer':
        raise AuthenticationFailed("Authorization header must start with 'Bearer'.")

    if len(parts) == 1:
        raise AuthenticationFailed("Token missing from Authorization header.")
    
    return parts[1]