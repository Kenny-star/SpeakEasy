from ._utils.email import send_verification_email
from ._utils._tokens import generate_verification_token
from api import settings
from rest_framework import serializers
from django.utils.timezone import now
from authentication.models import User, PasswordResetToken, RefreshToken as rt
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
from ._utils.helper import authenticate_login
# from models import *
import jwt

# User Serializer for Signup and Login
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'date_joined')
        read_only_fields = ('is_active', 'is_staff', 'is_superuser', 'date_joined')

class SignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password', 'password_confirm')

    def validate(self, data):
        # Check that passwords match
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        # Validate password strength using Django's password validation
        try:
            password_validation.validate_password(data['password'])
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})

        return data
    
    def create(self, validated_data):
        # Create the user
        validated_data.pop('password_confirm')  # Remove password_confirm before saving
        user = User.objects.create_user(**validated_data)

        # Generate the verification token (JWT)
        verification_token = generate_verification_token(user)

        # Send the verification email with the link
        send_verification_email(user.email, verification_token)

        # Return the user object after creation
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        # Validate credentials
        user = authenticate_login(email=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_active:
            raise serializers.ValidationError("Account not verified. Please verify your email.")

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # Try to get an existing refresh token for the user
        refresh_token_entry, created = rt.objects.get_or_create(
            user=user,
            defaults={
                'token': refresh_token,
                'created_at': now(),
                'expired_at': now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']  # Set your desired expiration time
            }
        )
        if not created or refresh_token_entry.is_expired():
            # Update the existing token if it already exists
            refresh_token_entry.token = refresh_token
            refresh_token_entry.created_at = now()
            refresh_token_entry.expired_at = now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            refresh_token_entry.save()

        
        return {
            'user': user,
            'access_token': access_token,
            'refresh_token': refresh_token,
        }
class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, data):
        refresh_token = data.get('refresh_token')
        try:
            # Check if the refresh token is expired in the DB
            refresh_token_instance = rt.objects.get(token=refresh_token)
            if refresh_token_instance.is_expired():
                raise serializers.ValidationError("Refresh token is expired. Login is required")

        except Exception as e:
            raise serializers.ValidationError("Invalid or expired refresh token.")

        return data

    def create(self, validated_data):
        # Use the refresh token to create a new access token
        refresh_token = validated_data['refresh_token']
        refresh = RefreshToken(refresh_token)

        # Generate a new access token
        access_token = str(refresh.access_token)

        return {
            'access_token': access_token,
        }
      

class RefreshTokenModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefreshToken
        fields = ['user', 'token', 'created_at', 'expired_at']

    def create(self, validated_data):
        refresh_token = validated_data.get('token')
        expired_at = validated_data.get('expired_at')

        # Ensure the refresh token is valid before saving it
        refresh_token_instance = RefreshToken(
            user=validated_data['user'],
            token=refresh_token,
            expired_at=expired_at,
        )
        refresh_token_instance.save()

        return refresh_token_instance
    
# Serializer to generate and verify password reset tokens
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        if not user:
            raise serializers.ValidationError("No user found with this email address.")
        return value

class PasswordResetTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetToken
        fields = ('token', 'user', 'created_at', 'expires_at')
        read_only_fields = ('user', 'created_at', 'expires_at')

    def create(self, validated_data):
        # Generate a random reset token
        reset_token = get_random_string(length=32)

        # Set expiration time (e.g., 1 hour from now)
        expiration_time = timezone.now() + timedelta(hours=1)

        # Create and store the reset token for the user
        password_reset_token = PasswordResetToken.objects.create(
            user=validated_data['user'],
            token=reset_token,
            expires_at=expiration_time
        )

        return password_reset_token

# Serializer to validate password reset
class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Check if the token exists and is valid
        try:
            reset_token = PasswordResetToken.objects.get(token=data['token'])
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Invalid reset token."})

        # Check if the token has expired
        if reset_token.is_expired():
            raise serializers.ValidationError({"token": "Reset token has expired."})

        # Check if the passwords match
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})

        # Validate password strength
        try:
            password_validation.validate_password(data['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})

        # Ensure the user is the one who requested the token
        self.context['reset_token'] = reset_token  # Store for later use in `save()`
        return data

    def save(self):
        # Reset the password
        reset_token = self.context['reset_token']
        user = reset_token.user
        user.set_password(self.validated_data['new_password'])
        user.save()

        # Mark the reset token as used (optional)
        reset_token.delete()

        return user

# Serializer for Email Verification
class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, token):
        try:
            # Decode the token to extract payload
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            # Ensure the required fields exist in the payload
            user_id = payload.get('user_id')
            email = payload.get('email')
            if not user_id or not email:
                raise serializers.ValidationError("Invalid token payload.")

            # Check if the user exists
            user = User.objects.get(id=user_id, email=email)
            if user.is_active:
                raise serializers.ValidationError("User is already verified.")

        except jwt.ExpiredSignatureError:
            raise serializers.ValidationError("Verification token has expired.")
        except jwt.InvalidTokenError:
            raise serializers.ValidationError("Invalid token.")
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        
        # Attach the user instance to the serializer for saving
        self.user = user
        return token

    def save(self):
        # Activate the user
        user = self.user
        user.is_active = True
        user.save()
        return user