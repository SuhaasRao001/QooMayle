"""
Test actual email sending with the updated email_handler
Run with: python scratch/test_send_email.py
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import email_handler

async def test_send():
    """Test sending an email with detailed output."""
    
    # FOR TESTING: Replace with your test credentials
    sender_email = input("Gmail address (with App Password): ").strip()
    sender_password = input("Gmail App Password (NOT your account password): ").strip()
    recipient = input("Recipient email: ").strip()
    
    if not all([sender_email, sender_password, recipient]):
        print("Error: All fields required")
        return
    
    print("\n" + "="*60)
    print("Testing email send with new timeout handling")
    print("="*60 + "\n")
    
    result = await email_handler.send_email(
        sender=sender_email,
        password=sender_password,
        recipient=recipient,
        subject="[TEST] QuMail Connection Test",
        encrypted_body="This is a test message from QuMail.",
        key_id=None,
        level=3,
        sender_sae_id="test_sender_123"
    )
    
    print("\n" + "="*60)
    if result["success"]:
        print("✓ SUCCESS: Email sent successfully!")
    else:
        print(f"✗ FAILED: {result['error']}")
        print("\nDiagnostic hints:")
        error = result['error'].lower()
        if "timeout" in error:
            print("  • Connection timeout - ISP may be blocking SMTP")
            print("  • Try using a VPN or different network")
        elif "auth" in error or "login" in error:
            print("  • Authentication failed")
            print("  • For Gmail: Use App Password, not account password")
            print("  • Enable 2FA: https://support.google.com/accounts/answer/185833")
            print("  • Generate App Password: https://myaccount.google.com/apppasswords")
        elif "certificate" in error or "ssl" in error or "tls" in error:
            print("  • SSL/TLS certificate issue")
            print("  • Update your system CA certificates")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(test_send())
