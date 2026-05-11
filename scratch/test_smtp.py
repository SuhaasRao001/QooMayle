import asyncio
import aiosmtplib
import socket
import ssl

async def test_port(hostname, port, use_tls, start_tls):
    print(f"\n--- Testing {hostname}:{port} (use_tls={use_tls}, start_tls={start_tls}) ---")
    try:
        # Test DNS resolution first
        try:
            info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            print(f"DNS resolved: {info[0]}")
        except socket.gaierror as e:
            print(f"DNS resolution failed: {e}")
            return False
            
        # Create SSL context for proper hostname verification
        tls_context = None
        if use_tls or start_tls:
            tls_context = ssl.create_default_context()
            tls_context.check_hostname = True
            tls_context.verify_mode = ssl.CERT_REQUIRED
        
        smtp = aiosmtplib.SMTP(
            hostname=hostname,
            port=port,
            use_tls=use_tls,
            timeout=15,
            tls_context=tls_context
        )
        print("Connecting...")
        await smtp.connect()
        print("Connected.")
        
        if start_tls:
            print("Starting TLS...")
            await smtp.starttls()
            print("TLS started.")
            
        await smtp.quit()
        print("SUCCESS")
        return True
        
    except asyncio.TimeoutError:
        print(f"TIMEOUT: Connection took too long (possible firewall/ISP blocking)")
        return False
    except ConnectionRefusedError:
        print(f"REFUSED: Port is closed or blocked")
        return False
    except socket.timeout:
        print(f"TIMEOUT: Socket timeout")
        return False
    except Exception as e:
        print(f"FAILED: {type(e).__name__}: {e}")
        return False

async def main():
    hostname = "smtp.gmail.com"
    print("=" * 60)
    print("Testing Gmail SMTP connectivity")
    print("=" * 60)
    
    # Standard ports - test 465 (implicit SSL) and 587 (STARTTLS)
    results = []
    results.append(("Port 465 (Implicit SSL)", await test_port(hostname, 465, True, False)))
    results.append(("Port 587 (STARTTLS)", await test_port(hostname, 587, False, True)))
    
    # Alternative ports (in case ISP blocks standard SMTP)
    print("\n" + "=" * 60)
    print("Testing alternative ports (if standard ports are blocked)")
    print("=" * 60)
    results.append(("Port 25 (Unencrypted SMTP)", await test_port(hostname, 25, False, False)))
    results.append(("Port 2525 (Alt TLS)", await test_port(hostname, 2525, False, True)))
    
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    for name, success in results:
        status = "✓ OK" if success else "✗ BLOCKED/FAILED"
        print(f"{name}: {status}")
    
    working = [name for name, success in results if success]
    if working:
        print(f"\n✓ Use one of these: {', '.join(working)}")
    else:
        print("\n✗ All ports failed. Your ISP likely blocks SMTP. Solutions:")
        print("  1. Use a VPN or proxy")
        print("  2. Contact ISP to unblock SMTP ports")
        print("  3. Use a mail relay service (e.g., SendGrid, Mailgun)")

if __name__ == "__main__":
    asyncio.run(main())
