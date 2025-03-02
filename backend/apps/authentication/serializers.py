from ._utils.email import *
from ._utils._tokens import generate_verification_token
from ._utils.helper import authenticate_login
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils.timezone import now
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from datetime import timedelta
from apps.authentication.models import User, PasswordResetToken, RefreshToken as rt
from django_ratelimit.decorators import ratelimit
from asgiref.sync import sync_to_async

import jwt

duration = settings.EMAIL_TOKEN_CONFIRMATION_EXPIRY

#EXAMPLE: To add objects from different model (will need to append info from player stats and resume in api)

# class PasswordResetTokenSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = PasswordResetToken
#         fields = ('token', 'created_at', 'expired_at')

class UserSerializer(serializers.ModelSerializer):

    # Include the related PasswordResetToken instances
    # reset_tokens = PasswordResetTokenSerializer(source='passwordresettoken_set', many=True, read_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'date_joined')
        # fields = ('id', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'date_joined', 'reset_tokens')
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
        
        validated_data.pop('password_confirm')  
        # Hash the password before saving
        password = validated_data.pop('password')
        hashed_password = make_password(password)

        with transaction.atomic():
            user, created = User.objects.get_or_create(
                email=validated_data['email'],
                defaults={
                    **validated_data,
                    'password': hashed_password  # Save the hashed password
                }
            )
        
        if not created:
            pass
        
        # Generate the verification token (JWT)
        verification_token = generate_verification_token(user, duration)

        # Send the verification email with the link
        send_verification_email_async(user.email, verification_token, "login", duration)

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

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        if not user.is_active:
            verification_token = generate_verification_token(user, duration)
            send_verification_email_async(user.email, verification_token, "login", duration)
            raise serializers.ValidationError("Please verify your email.")
        
        if user.is_active:
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
                'access_token': access_token,
                'refresh_token': refresh_token,
            }
class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, data):
        refresh_token = data.get('refresh_token')
        try:
            refresh_token_instance = rt.objects.get(token=refresh_token)
            if refresh_token_instance.is_expired():
                raise serializers.ValidationError("Refresh token is expired")

            try:
                self.refresh = RefreshToken(refresh_token)
            except Exception:
                raise serializers.ValidationError("Invalid refresh token format")

            return data

        except rt.DoesNotExist:
            raise serializers.ValidationError("Refresh token not found")
        except Exception as e:
            raise serializers.ValidationError(str(e))

    def create(self, validated_data):
        return {
            'access_token': str(self.refresh.access_token),
        }
      
# Serializer to generate and verify password reset tokens
@ratelimit(key=settings.PASSWORD_RESET_KEY, rate=settings.PASSWORD_RESET_RATE, block=True)
class PasswordResetTokenSerializer(serializers.ModelSerializer):

    email = serializers.EmailField()

    class Meta:
        model = PasswordResetToken
        fields = ('user', 'email', 'created_at', 'expired_at')
        read_only_fields = ('user', 'created_at', 'expired_at')

    def validate(self, data):
        user = User.objects.filter(email=data['email']).first()
        if not user:
            raise serializers.ValidationError("No user found with this email address.")
        

        data['user'] = user
        return data
    
    def create(self, validated_data):
        msg = ""
        try:
            # Retrieve user from validated data
            user = validated_data.get('user')
            if not user:
                raise serializers.ValidationError("User not found in validated data.")
            
            # Fetch both valid and expired tokens in one query
            tokens = PasswordResetToken.objects.filter(user=user)

            # Split tokens into valid and expired
            valid_tokens = [token for token in tokens if token.expired_at > timezone.now()]
            expired_tokens = [token for token in tokens if token.expired_at <= timezone.now()]

            # If there are expired tokens, delete them
            PasswordResetToken.objects.filter(id__in=[token.id for token in expired_tokens]).delete()

            # If there is a valid token, assign it
            existing_token = valid_tokens[0] if valid_tokens else None

            if existing_token:
                # If there's an existing valid token, do not generate a new one
                msg += "Non-expired password reset token is already sent to your email. (<10min)"
                return existing_token, msg
                
        
            token, duration = None, settings.EMAIL_TOKEN_CONFIRMATION_EXPIRY
            expiry_time = timezone.now() + duration  # Token expires in 10 minutes
                
            for _ in range(100):
                try:
                    token = get_random_string(32)  # Generate a 32-character random string for token
                    # Create and store the reset token for the user
                    pwd, created = PasswordResetToken.objects.get_or_create(
                        user=user,
                        token=token,
                        expired_at=expiry_time
                    )
                    if created:
                        send_verification_email_async(user.email, token, "reset-password", duration)
                        msg += "Password reset link has been sent to your email."
                        return pwd, msg
                    
                except IntegrityError:
                    # If a collision occurs (duplicate user-email/token), retry with a new token
                    continue
                        
        except serializers.ValidationError("Failed to create a unique token.") as e:
            # Handle the validation error (e.g., log it, raise it again, or return a response)
            raise e  # or handle the exception as needed
        
# Serializer to validate password reset
class PasswordResetConfirmSerializer(serializers.ModelSerializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model: PasswordResetToken
        fields = '__all__'
        
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
        try:            # Decode the token to extract payload
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.SIMPLE_JWT['ALGORITHM']])
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