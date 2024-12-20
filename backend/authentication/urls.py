from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('email-verification/', EmailVerificationView.as_view(), name='email-verification'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('login/', LoginView.as_view(), name='login'),
    
]
