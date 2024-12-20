import jwt

from datetime import datetime, timedelta
from api import settings
from django.utils.timezone import now

def generate_verification_token(user):
        # Create a JWT token with user details and expiration time
        payload = {
            'user_id': user.id,
            'email': user.email,
            'exp': now() + timedelta(days=1),  # Token expires in 1 day
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')