from django.core.mail import send_mail
from api import settings


def send_verification_email(email, token):
        # Construct the verification URL (you can customize the frontend URL)
        verification_url = f"{settings.FRONTEND_EMAIL_VERIFICATION_URL}{token}"

        # Send email to user (make sure you have email backend configured)
        send_mail(
            'Verify your email',
            f'Hello! Please verify your email by clicking the following link: {verification_url}\n\n'
            f'This link will expire in 24 hours.',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
