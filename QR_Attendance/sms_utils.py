import requests
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMSHandler:
    def __init__(self, sid, token, from_number):
        self.sid = sid
        self.token = token
        self.from_number = from_number
        self.api_url = f"https://api.twilio.com/2010-04-01/Accounts/{self.sid}/Messages.json"

    def send_sms(self, to_number, message_body):
        """
        Sends an SMS using the Twilio REST API.
        """
        if not self.sid or not self.token or not self.from_number:
            logger.error("SMS credentials missing.")
            return False, "Credentials missing"

        try:
            # Twilio expects E.164 format. If it's 10 digits, assume +91 (India) or similar
            # For robustness, we should ideally handle this in the UI or here.
            formatted_to = to_number
            if len(to_number) == 10:
                formatted_to = "+91" + to_number # Default to India for this project context
            elif not to_number.startswith('+'):
                formatted_to = "+" + to_number

            response = requests.post(
                self.api_url,
                data={
                    "To": formatted_to,
                    "From": self.from_number,
                    "Body": message_body
                },
                auth=(self.sid, self.token),
                timeout=10
            )

            if response.status_code == 201:
                logger.info(f"SMS sent successfully to {formatted_to}")
                return True, "SENT"
            else:
                try:
                    data = response.json()
                    twilio_code = data.get('code', 'No Code')
                    error_details = data.get('message', 'No message')
                    error_msg = f"Twilio Error {twilio_code}: {error_details}"
                except Exception:
                    # Capture more of the response text for debugging
                    error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                
                logger.error(f"Failed to send SMS to {formatted_to}. Status: {response.status_code}. Details: {error_msg}")
                return False, error_msg

        except Exception as e:
            logger.error(f"SMS Gateway Exception: {str(e)}")
            return False, str(e)

def format_absence_message(student_name, subject, date, attendance_pct=None, threshold=75, institution="CHAITANYA ENGINEERING COLLEGE"):
    """
    Formats a professional absence message with optional attendance warning.
    """
    if attendance_pct is not None and attendance_pct < threshold:
        return (f"[{institution}] ATTENDANCE WARNING: Your ward {student_name} was ABSENT for {subject} on {date}. "
                f"Current attendance is {attendance_pct:.1f}%, which is below the mandatory {threshold}%. "
                f"Please ensure regular attendance.")
    
    return (f"[{institution}] Absence Notification: Please be informed that your ward {student_name} was marked "
            f"ABSENT for the {subject} session on {date}. Current attendance: "
            f"{f'{attendance_pct:.1f}%' if attendance_pct is not None else 'N/A'}. Regards.")
