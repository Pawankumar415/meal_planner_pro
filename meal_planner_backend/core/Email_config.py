import pytz
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import bcrypt
from pydantic import EmailStr, BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta


load_dotenv()


######################################################################################################################
                # For sending Email
#######################################################################################################################

async def send_email(subject, email_to, body):
    # Set up the SMTP server
    smtp_server = os.getenv("smtp_server_name")
    smtp_port = os.getenv("smtp_port_name")
    smtp_username = os.getenv("smtp_username_name")  
    smtp_password = os.getenv("smtp_password_name") 
    try:
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  
        server.login(smtp_username, smtp_password)  
        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email_to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        server.sendmail(smtp_username, email_to, msg.as_string())
        server.quit()

    except Exception as e:
        
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

############################################################################################################

async def send_otp_email(user_email: str, otp_code: str):
    # Set timezone to IST
    ist = pytz.timezone('Asia/Kolkata')

    # Get current UTC time, localize it, and convert to IST
    utc_now = pytz.utc.localize(datetime.utcnow())
    ist_now = utc_now.astimezone(ist)

    # Calculate expiry time in IST
    expiry_time_ist = ist_now + timedelta(minutes=5)
    formatted_expiry = expiry_time_ist.strftime('%I:%M %p IST')

    # Email body
    body = f"""
    <h3>OTP Verification</h3>
    <p>Your One-Time Password (OTP) for login is:</p>
    <h2 style="color: #2e6c80;">{otp_code}</h2>
    <p>This OTP is valid until <b>{formatted_expiry}</b> (5 minutes).</p>
    <p>If you did not request this, please ignore this message.</p>
    <br>
    <p>Best regards,</p>
    <p>Vinay Kumar</p>
    <p>MaitriAI</p>
    <p>900417181</p>
    """

    try:
        await send_email(
            subject="Your OTP Code for Login",
            email_to=user_email,
            body=body
        )
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send OTP. Please try again later.")
