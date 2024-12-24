from venv import logger
from django.core.mail import send_mail
from api import settings
from .time import convert_time_string
from celery import shared_task

@shared_task
def send_verification_email_async(email, token, type, duration):
    # Construct the verification URL (you can customize the frontend URL)
    try:
        verification_url = f"{settings.FRONTEND_EMAIL_VERIFICATION_URL}{token}" if type == "login" else \
                           f"{settings.FRONTEND_EMAIL_RESET_PASSWORD_URL}{token}"
        send_mail(
            'Verify your email',
            f'Hello! \n\nPlease verify your email by clicking the following link: {verification_url}\n\n'
            f'This link will expire in {convert_time_string(str(duration))}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
