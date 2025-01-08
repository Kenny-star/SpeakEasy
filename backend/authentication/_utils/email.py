from venv import logger
from django.core.mail import send_mail
from api import settings
from .time import convert_time_string
from django.utils.html import format_html
from celery import shared_task

@shared_task
def send_verification_email_async(email, token, type, duration):
    try:
        verification_url = f"{settings.FRONTEND_EMAIL_VERIFICATION_URL}{token}" if type == "login" else \
                           f"{settings.FRONTEND_EMAIL_RESET_PASSWORD_URL}{token}"
        
        send_mail(
            subject='Verify Your Email',
            message='',  # Leave the plain text version blank
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
            html_message=format_html(
                """
        <html>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333;">
            <table cellpadding="0" cellspacing="0" border="0" style="width: 100%; max-width: 600px; margin: 20px auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
                <tr>
                    <td style="background-color: #0056b3; padding: 20px; text-align: center;">
                        <h1 style="color: #fff; font-size: 24px; margin: 0;">Verify Your Email</h1>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 20px;">
                        <p style="font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
                            Hello,
                        </p>
                        <p style="font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
                            Please verify your email by clicking the button below:
                        </p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{verification_url}" style="
                                display: inline-block;
                                padding: 12px 25px;
                                font-size: 16px;
                                color: #fff;
                                background-color: #0056b3;
                                text-decoration: none;
                                border-radius: 5px;
                                font-weight: bold;
                            ">Verify Email</a>
                        </p>
                        <p style="font-size: 14px; line-height: 1.5; color: #666; text-align: center; margin: 10px 0;">
                            Or copy and paste this link into your browser: <br>
                            <a href="{verification_url}" style="color: #0056b3; word-break: break-all;">{verification_url}</a>
                        </p>
                        <p style="font-size: 14px; line-height: 1.5; color: #666; margin: 10px 0;">
                            This link will expire in <strong>{duration}</strong>.
                        </p>
                    </td>
                </tr>
                <tr>
                    <td style="background-color: #f2f2f2; padding: 10px; text-align: center; font-size: 12px; color: #999;">
                        If you didn’t request this, you can safely ignore this email.
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """,
                verification_url=verification_url,
                duration=convert_time_string(str(duration)),
            ),
        )
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
