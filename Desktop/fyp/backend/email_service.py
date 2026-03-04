"""
email_service.py — Real SMTP email sending for XSSniper.
Used for forgot-password emails. No dummy/mock data.
"""

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from backend.config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, APP_BASE_URL


def send_password_reset_email(to_email: str, username: str, token: str) -> tuple[bool, str]:
    """
    Send a real password reset email via SMTP.
    Returns (success: bool, error_message: str).
    """
    if not SMTP_USER or not SMTP_PASS:
        return False, "Email service not configured. Please set SMTP_USER and SMTP_PASS in your .env file."

    reset_link = f"{APP_BASE_URL}/reset-password?token={token}"

    # ── Plain text body ──────────────────────────────────────
    text_body = f"""Hi {username},

You requested a password reset for your XSSniper account.

Click the link below to reset your password (valid for 1 hour):
{reset_link}

If you did not request this, ignore this email — your password will not change.

— XSSniper Security Team
"""

    # ── HTML body ────────────────────────────────────────────
    html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#020408;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#020408;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#0a1520;border:1px solid #1a2e40;border-radius:16px;overflow:hidden;max-width:560px;">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d1f2d,#0a2a1e);padding:32px 40px;text-align:center;border-bottom:1px solid #00ff8833;">
              <div style="font-size:32px;margin-bottom:8px;">🛡️</div>
              <div style="font-size:22px;font-weight:800;color:#00ff88;letter-spacing:4px;font-family:'Courier New',monospace;">XSSNIPER</div>
              <div style="font-size:11px;color:#4a6a7a;letter-spacing:3px;margin-top:4px;">ML-ENHANCED SCANNER</div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              <p style="color:#7c8fa6;font-size:14px;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:2px;">Password Reset Request</p>
              <h2 style="color:#e2e8f0;font-size:20px;margin:0 0 20px 0;">Hi {username},</h2>
              <p style="color:#a0b4c8;font-size:15px;line-height:1.7;margin:0 0 28px 0;">
                We received a request to reset the password for your XSSniper account.
                Click the button below to choose a new password.
              </p>

              <!-- Reset Button -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding:8px 0 28px 0;">
                    <a href="{reset_link}"
                       style="display:inline-block;background:#00ff88;color:#000;font-weight:700;font-size:14px;
                              letter-spacing:2px;text-decoration:none;padding:14px 40px;border-radius:8px;
                              font-family:'Courier New',monospace;">
                      RESET PASSWORD
                    </a>
                  </td>
                </tr>
              </table>

              <p style="color:#7c8fa6;font-size:13px;line-height:1.6;margin:0 0 16px 0;">
                Or copy and paste this link into your browser:
              </p>
              <div style="background:#060d14;border:1px solid #1a2e40;border-radius:8px;padding:12px 16px;
                          font-family:'Courier New',monospace;font-size:12px;color:#00d9ff;word-break:break-all;">
                {reset_link}
              </div>

              <!-- Warning box -->
              <div style="background:#0d0a00;border:1px solid #f59e0b33;border-radius:8px;padding:16px;margin-top:24px;">
                <p style="color:#f59e0b;font-size:13px;margin:0 0 6px 0;font-weight:600;">⚠ Important</p>
                <p style="color:#8a7a50;font-size:13px;margin:0;line-height:1.6;">
                  This link expires in <strong style="color:#f59e0b;">1 hour</strong>.
                  If you did not request a password reset, you can safely ignore this email.
                  Your password will not change.
                </p>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#060d14;padding:20px 40px;border-top:1px solid #1a2e40;text-align:center;">
              <p style="color:#3d5166;font-size:12px;margin:0;font-family:'Courier New',monospace;">
                XSSniper Security Team &nbsp;|&nbsp; Do not reply to this email
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "XSSniper — Password Reset Request"
        msg["From"]    = SMTP_FROM
        msg["To"]      = to_email

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())

        return True, ""

    except smtplib.SMTPAuthenticationError:
        return False, "Email authentication failed. Check SMTP_USER and SMTP_PASS in your .env file."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"
