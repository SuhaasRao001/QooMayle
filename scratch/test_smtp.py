import asyncio
import aiosmtplib
import socket

async def test_port(hostname, port, use_tls, start_tls):
    print(f"\n--- Testing {hostname}:{port} (use_tls={use_tls}, start_tls={start_tls}) ---")
    try:
        smtp = aiosmtplib.SMTP(hostname=hostname, port=port, use_tls=use_tls, timeout=10)
        print("Connecting...")
        await smtp.connect()
        print("Connected.")
        if start_tls:
            print("Starting TLS...")
            await smtp.starttls()
            print("TLS started.")
        await smtp.quit()
        print("SUCCESS")
    except Exception as e:
        print(f"FAILED: {e}")

async def main():
    hostname = "smtp.gmail.com"
    # Test 587 with STARTTLS
    await test_port(hostname, 587, False, True)
    # Test 465 with Implicit SSL
    await test_port(hostname, 465, True, False)

if __name__ == "__main__":
    asyncio.run(main())
