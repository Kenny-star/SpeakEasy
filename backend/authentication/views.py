from authentication.serializers import *
from ._utils.helper import create_cookie
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.models import *
from authentication.models import RefreshToken as rt
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.hashers import check_password, make_password
from django.conf import settings
from django.urls import reverse
from django.http import JsonResponse
from rest_framework.permissions import AllowAny, IsAuthenticated
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError

access_token_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
refresh_token_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']

class SignupView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        
        serializer = SignupSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            serializer.save()

            return Response({'message': 'Verification email sent!'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# http://127.0.0.1:8000/email-verification/?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Imtlbm55Lmx1b2xpQGhvdG1haWwuY2EiLCJleHAiOjE3MzQ2MzE0MzB9.BvxbK_Nci2dncYOAwe_Mkiyvac8sXe0aYYL3wU4OuhE
class EmailVerificationView(APIView):
    authentication_classes = [] 
    permission_classes = [AllowAny]
    def get(self, request):
        token = request.GET.get('token')

        if not token:
            return JsonResponse({"error": "Token is required."}, status=400)

        # Pass the token to the serializer for validation
        serializer = EmailVerificationSerializer(data={"token": token})
        if serializer.is_valid(raise_exception=True):
            # Activate the user and save
            serializer.save()
            return JsonResponse({"message": "Email verified successfully."}, status=200)

        # Return validation errors if the token is invalid
        return JsonResponse(serializer.errors, status=400)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        token_serializer= PasswordResetTokenSerializer(data=request.data)
        if token_serializer.is_valid(raise_exception=True):
            # Send the reset link via email (pseudo-code for email sending)
            token_serialized, msg = token_serializer.save()  # Save the token and get the object

            return Response(
                {"message": msg},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(token_serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):

        token = request.GET.get('token')
        new_password = request.data.get('new_password')

        # Check if user exists
        try:
            # Get user by token
            user = PasswordResetToken.get_user_by_token(token)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check password history to prevent reusing old passwords
        password_history = PasswordHistory.objects.filter(user=user)

        for entry in password_history:
            if check_password(new_password, entry.password_hash):
                return Response({'error': 'Cannot reuse an old password'}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password
        user.set_password(new_password)
        user.save()

        # Add the new password to history
        PasswordHistory.objects.create(user=user, password_hash=make_password(new_password))

        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)


class LoginView(APIView):
    authentication_classes = [] 
    permission_classes = [AllowAny]

    def post(self, request):
        # Use the LoginSerializer to validate input and authenticate user
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Extract validated data
        # user = serializer.validated_data['user']
        access_token = serializer.validated_data['access_token']
        refresh_token = serializer.validated_data['refresh_token']

        # Create the response
        response = JsonResponse({'message': 'Login successful'})

        # Set JWT tokens in HTTP-only cookies
        create_cookie(response, 'access_token', access_token, access_token_lifetime)
        create_cookie(response, 'refresh_token', refresh_token, refresh_token_lifetime)

        return response
    
class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return JsonResponse({"error": "Refresh token not found"}, status=400)
            
        try:
            # Pass the refresh token to the serializer
            serializer = RefreshTokenSerializer(data={"refresh_token": refresh_token})

            if serializer.is_valid(raise_exception=True):
                # Get new access token
                new_access_token = serializer.save()
                # Create response
                response = JsonResponse({"access_token": new_access_token['access_token']}, status=status.HTTP_200_OK)

                # Set new access token in cookies
                create_cookie(response, 'access_token', new_access_token['access_token'], access_token_lifetime.total_seconds())

                return response
        except Exception as e:

            return JsonResponse({"error": "Invalid refresh token"}, status=400)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return JsonResponse({"error": "Refresh token not found"}, status=400)
        try:
            refresh_token_obj = rt.objects.get(token=refresh_token)
            
            if refresh_token_obj.is_expired():
                return JsonResponse({"error": "Refresh token expired"}, status=400)

            serializer = UserSerializer(refresh_token_obj.user)

            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            # Handle the case where the user doesn't exist
            return JsonResponse({"error": "User not found"}, status=404)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            updated = User.objects.filter(
                id=rt.objects.filter(token=refresh_token).values('user_id')
            ).update(is_active=False)

            response = JsonResponse({'message': 'Logout successful'})
            response.set_cookie('access_token', '', max_age=0)
            response.set_cookie('refresh_token', '', max_age=0)
            
            return response
        
        except rt.DoesNotExist:
            return JsonResponse({"error": "Refresh Token not found"}, status=404)