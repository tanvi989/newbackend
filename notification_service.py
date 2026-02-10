import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import config
import logging

# Branding for emails (use https so images load in email clients)
LOGO_URL = "https://cdn.multifolks.com/desktop/images/multifolks-logo.svg"
COMPANY_ADDRESS = "2 Leman Street, London, E1W 9US"
COMPANY_NAME = "MultiFolks"
WEBSITE_URL = "https://www.multifolks.com"
SUPPORT_EMAIL = "support@multifolks.com"
# Primary brand color (orange-red) for thank-you email
PRIMARY_COLOR = "#F4522B"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MSG91Service:
    def __init__(self):
        self.auth_key = config.MSG91_AUTH_KEY
        self.domain = config.MSG91_DOMAIN
        self.sender_email = config.MSG91_SENDER_EMAIL
        self.sender_name = config.MSG91_SENDER_NAME
        self.base_url = "https://control.msg91.com/api/v5/email/send"
        
        logger.info(f"MSG91 Service initialized - Domain: {self.domain}, Sender: {self.sender_email}")

    def send_email(self, to_email: str, template_id: str, variables: dict):
        """
        Send email using MSG91 API with detailed logging.
        
        Args:
            to_email: Recipient email address
            template_id: MSG91 template ID
            variables: Dictionary of template variables
            
        Returns:
            dict: Response with success status and data/error message
        """
        logger.info(f"[MSG91] Preparing to send email")
        logger.info(f"   Template: {template_id}")
        logger.info(f"   To: {to_email}")
        logger.info(f"   Variables: {list(variables.keys())}")
        
        if not self.auth_key or not self.domain:
            logger.error("[ERR] MSG91 credentials not configured")
            print("[ORDER EMAIL] MSG91 not configured: missing MSG91_AUTH_KEY or MSG91_DOMAIN in .env")
            return {"success": False, "msg": "MSG91 not configured"}

        payload = {
            "recipients": [
                {
                    "to": [
                        {
                            "name": variables.get("name", variables.get("NAME", "User")),
                            "email": to_email
                        }
                    ],
                    "variables": variables
                }
            ],
            "from": {
                "email": self.sender_email,
                "name": self.sender_name
            },
            "domain": self.domain,
            "template_id": template_id
        }

        headers = {
            "authkey": self.auth_key,
            "Content-Type": "application/json"
        }
        
        logger.info(f"[MSG91] Sending request to {self.base_url}")

        try:
            response = requests.post(self.base_url, json=payload, headers=headers)
            logger.info(f"[MSG91] Response status {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                unique_id = response_data.get('data', {}).get('unique_id', 'N/A')
                logger.info(f"[OK] MSG91: Email queued successfully")
                logger.info(f"   Unique ID: {unique_id}")
                print(f"[ORDER EMAIL] MSG91 accepted email (unique_id: {unique_id})")
                return {"success": True, "data": response_data}
            else:
                logger.error(f"[ERR] MSG91: Failed with status {response.status_code}")
                logger.error(f"   Response: {response.text}")
                print(f"[ORDER EMAIL] MSG91 API failed: status {response.status_code}, response: {response.text[:200]}")
                return {"success": False, "msg": f"Failed to send email: {response.text}"}
        except Exception as e:
            logger.error(f"[ERR] MSG91: Exception occurred: {str(e)}")
            print(f"[ORDER EMAIL] MSG91 exception: {e}")
            return {"success": False, "msg": str(e)}

    def send_login_pin(self, email: str, pin: str, name: str = None):
        """
        Send login PIN via email.
        """
        logger.info(f"[MSG91] Sending login PIN to {email}")
        template_id = config.MSG91_TEMPLATE_ID
        if not template_id:
            logger.error("[ERR] MSG91_TEMPLATE_ID not configured")
            return {"success": False, "msg": "Template ID missing"}
            
        variables = {
            "oneTimePin": pin,
            "firstName": name or "User",
            # Keep old ones for backward compatibility if needed, or remove them. 
            # Given the image is specific, best to include exactly what's needed plus common variations if unsure, 
            # but user said "its like this", so I will prioritize the new ones.
            "OTP": pin,
            "name": name or "User"
        }
        
        return self.send_email(email, template_id, variables)

    def send_password_reset_pin(self, email: str, pin: str, name: str = None):
        """
        Send password reset PIN via email.
        """
        logger.info(f"[MSG91] Sending password reset PIN to {email}")
        template_id = config.MSG91_RESET_TEMPLATE_ID or config.MSG91_TEMPLATE_ID
        if not template_id:
            logger.error("[ERR] MSG91_RESET_TEMPLATE_ID not configured")
            return {"success": False, "msg": "Template ID missing"}
            
        variables = {
            "oneTimePin": pin,
            "firstName": name or "User",
            "OTP": pin,
            "name": name or "User"
        }
        
        return self.send_email(email, template_id, variables)

    def send_welcome_email(self, email: str, name: str = None, password: str = None):
        """
        Send welcome email to new users.
        """
        logger.info(f"[MSG91] Sending welcome email to {email}")
        template_id = config.MSG91_WELCOME_TEMPLATE_ID
        if not template_id:
            logger.error("[ERR] MSG91_WELCOME_TEMPLATE_ID not configured")
            return {"success": False, "msg": "Welcome template ID missing"}
            
        variables = {
            "NAME": name or "User",
            "name": name or "User",
            "email": email
        }
        
        if password:
            variables["PASSWORD"] = password
            variables["password"] = password
        
        return self.send_email(email, template_id, variables)

    def send_order_confirmation(self, email: str, order_id: str, order_total: str = None, name: str = None):
        """
        Send order confirmation email.
        """
        logger.info(f"[MSG91] Sending order confirmation to {email}")
        logger.info(f"   Order ID: {order_id}, Total: {order_total}")
        template_id = config.MSG91_ORDER_TEMPLATE_ID
        if not template_id:
            logger.error("[ERR] MSG91_ORDER_TEMPLATE_ID not configured")
            print("[ORDER EMAIL] Order template not set: add MSG91_ORDER_TEMPLATE_ID to .env")
            return {"success": False, "msg": "Order template ID missing"}
            
        variables = {
            "NAME": name or "User",
            "name": name or "User",
            "order_id": order_id,
            "ORDER_ID": order_id,
            "email": email
        }
        
        if order_total:
            variables["order_total"] = order_total
            variables["ORDER_TOTAL"] = order_total
        
        return self.send_email(email, template_id, variables)

    def _email_html_template(self, title: str, body_html: str) -> str:
        """Wrap content in a consistent HTML email layout with logo and address."""
        return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
</head>
<body style="margin:0; padding:0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 24px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background: #ffffff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden;">
          <tr>
            <td style="padding: 32px 40px 24px; text-align: center; background: #fafafa; border-bottom: 1px solid #eee;">
              <img src="{LOGO_URL}" alt="{COMPANY_NAME}" width="180" height="auto" style="display: inline-block; max-width: 180px; height: auto;" />
            </td>
          </tr>
          <tr>
            <td style="padding: 32px 40px;">
              {body_html}
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px 32px; background: #fafafa; border-top: 1px solid #eee; font-size: 13px; color: #666; line-height: 1.6;">
              <strong style="color: #2C2C29;">{COMPANY_NAME}</strong><br/>
              {COMPANY_ADDRESS}<br/>
              <a href="mailto:support@multifolks.com" style="color: #025048; text-decoration: none;">support@multifolks.com</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    def _thank_you_email_html(self, first_name: str) -> str:
        """Thank-you email in primary orange-red with white text, logo, website, email and address."""
        return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Thank you – MultiFolks</title>
</head>
<body style="margin:0; padding:0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 24px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width: 600px; background: {PRIMARY_COLOR}; border-radius: 0; overflow: hidden;">
          <tr>
            <td style="padding: 40px 40px 24px 40px;">
              <img src="{LOGO_URL}" alt="{COMPANY_NAME}" width="160" height="auto" style="display: block; max-width: 160px; height: auto; filter: brightness(0) invert(1);" />
            </td>
          </tr>
          <tr>
            <td style="padding: 0 40px 32px; color: #ffffff;">
              <h2 style="margin: 0 0 20px; font-size: 24px; font-weight: 600; color: #ffffff;">Thank you for getting in touch</h2>
              <p style="margin: 0 0 16px; font-size: 16px; color: #ffffff; line-height: 1.6;">Dear {first_name},</p>
              <p style="margin: 0 0 24px; font-size: 16px; color: #ffffff; line-height: 1.6;">We have received your message and will connect with you shortly.</p>
              <p style="margin: 0; font-size: 15px; color: rgba(255,255,255,0.95); line-height: 1.6;">If your query is urgent, reach us using the details below.</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 0 40px 24px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr><td style="border-bottom: 1px solid rgba(255,255,255,0.4); padding: 10px 0 8px; font-size: 14px; color: #ffffff;"><a href="{WEBSITE_URL}" style="color: #ffffff; text-decoration: none;">Website</a></td></tr>
                <tr><td style="border-bottom: 1px solid rgba(255,255,255,0.4); padding: 10px 0 8px; font-size: 14px; color: #ffffff;"><a href="mailto:{SUPPORT_EMAIL}" style="color: #ffffff; text-decoration: none;">{SUPPORT_EMAIL}</a></td></tr>
                <tr><td style="border-bottom: 1px solid rgba(255,255,255,0.4); padding: 10px 0 8px; font-size: 14px; color: #ffffff;">{COMPANY_ADDRESS}</td></tr>
                <tr><td style="padding: 10px 0 0; font-size: 13px; color: rgba(255,255,255,0.9);">{COMPANY_NAME}</td></tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    def _send_smtp_html(self, to_email: str, subject: str, html_content: str) -> dict:
        """Send a single HTML email via SMTP. Returns {success: bool, msg?: str}."""
        if not config.SMTP_EMAIL or not config.SMTP_APP_PASSWORD:
            return {"success": False, "msg": "SMTP not configured"}

        msg = MIMEMultipart("alternative")
        msg["From"] = formataddr((COMPANY_NAME, config.SMTP_EMAIL))
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        for name, port, use_ssl in [("STARTTLS", 587, False), ("SSL", 465, True)]:
            try:
                if use_ssl:
                    with smtplib.SMTP_SSL(config.SMTP_HOST, port, timeout=15) as server:
                        server.login(config.SMTP_EMAIL, config.SMTP_APP_PASSWORD)
                        server.sendmail(config.SMTP_EMAIL, to_email, msg.as_string())
                else:
                    with smtplib.SMTP(config.SMTP_HOST, port, timeout=15) as server:
                        server.starttls()
                        server.login(config.SMTP_EMAIL, config.SMTP_APP_PASSWORD)
                        server.sendmail(config.SMTP_EMAIL, to_email, msg.as_string())
                logger.info("[SMTP] Email sent to %s: %s", to_email, subject)
                return {"success": True}
            except Exception as e:
                logger.warning("[SMTP] %s port %s failed: %s", name, port, e)
                continue
        return {"success": False, "msg": "All SMTP attempts failed"}

    def send_contact_form_notification(self, to_email: str, first_name: str, last_name: str,
                                       sender_email: str, phone: str, comment: str):
        """
        Send (1) contact form details to admin and (2) thank-you email to the person who submitted.
        Uses HTML design with logo and address. Set SMTP_EMAIL, SMTP_APP_PASSWORD, CONTACT_FORM_TO_EMAIL in .env.
        """
        if not config.SMTP_EMAIL or not config.SMTP_APP_PASSWORD:
            logger.warning("[SMTP] Contact form email skipped: SMTP_EMAIL or SMTP_APP_PASSWORD not set in .env")
            return {"success": False, "msg": "SMTP not configured"}

        logger.info("[SMTP] Sending contact form notification to %s and thank-you to %s", to_email, sender_email)

        # Escape for HTML
        def esc(s):
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        # 1) Admin email: new submission
        admin_body = f"""
          <h2 style="margin: 0 0 20px; font-size: 20px; color: #2C2C29;">New Contact Form Submission</h2>
          <p style="margin: 0 0 24px; font-size: 15px; color: #444; line-height: 1.6;">A new message was received from your website.</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border: 1px solid #e5e5e5; border-radius: 8px; overflow: hidden;">
            <tr style="background: #fafafa;"><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29; width: 140px;">First Name</td><td style="padding: 12px 16px; color: #444;">{esc(first_name)}</td></tr>
            <tr><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29;">Last Name</td><td style="padding: 12px 16px; color: #444;">{esc(last_name)}</td></tr>
            <tr style="background: #fafafa;"><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29;">Email</td><td style="padding: 12px 16px;"><a href="mailto:{esc(sender_email)}" style="color: #025048;">{esc(sender_email)}</a></td></tr>
            <tr><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29;">Phone</td><td style="padding: 12px 16px; color: #444;">{esc(phone)}</td></tr>
            <tr style="background: #fafafa;"><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29; vertical-align: top;">Message</td><td style="padding: 12px 16px; color: #444; white-space: pre-wrap;">{esc(comment)}</td></tr>
          </table>
        """
        admin_html = self._email_html_template("New Contact – MultiFolks", admin_body)
        admin_ok = self._send_smtp_html(to_email, "New Contact Form Submission – MultiFolks", admin_html)

        # 2) Thank-you email in primary brand color (orange-red), white text, logo, website & contact
        thank_you_html = self._thank_you_email_html(esc(first_name))
        thank_ok = self._send_smtp_html(sender_email, "Thank you for contacting MultiFolks", thank_you_html)

        if admin_ok.get("success") and thank_ok.get("success"):
            return {"success": True}
        if not admin_ok.get("success"):
            return admin_ok
        return thank_ok

    def send_newsletter_subscription_notification(self, to_email: str, subscriber_email: str):
        """
        Send one email to admin when someone subscribes to the newsletter.
        Uses same SMTP and CONTACT_FORM_TO_EMAIL as contact form.
        """
        if not config.SMTP_EMAIL or not config.SMTP_APP_PASSWORD:
            logger.warning("[SMTP] Newsletter notification skipped: SMTP not configured")
            return {"success": False, "msg": "SMTP not configured"}

        def esc(s):
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        body = f"""
          <h2 style="margin: 0 0 20px; font-size: 20px; color: #2C2C29;">New Newsletter Subscription</h2>
          <p style="margin: 0 0 24px; font-size: 15px; color: #444; line-height: 1.6;">Someone just subscribed to your newsletter.</p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border: 1px solid #e5e5e5; border-radius: 8px; overflow: hidden;">
            <tr style="background: #fafafa;"><td style="padding: 12px 16px; font-weight: 600; color: #2C2C29; width: 140px;">Email</td><td style="padding: 12px 16px;"><a href="mailto:{esc(subscriber_email)}" style="color: #025048;">{esc(subscriber_email)}</a></td></tr>
          </table>
        """
        html = self._email_html_template("New Newsletter Subscription – MultiFolks", body)
        return self._send_smtp_html(to_email, "New Newsletter Subscription – MultiFolks", html)
