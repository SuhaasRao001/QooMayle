"""
Network & SMTP diagnostics
Run: python scratch/diagnose.py
"""
import socket
import asyncio

def test_dns():
    """Test DNS resolution."""
    print("\n=== DNS Resolution ===")
    hosts = [
        ("smtp.gmail.com", 465),
        ("smtp.gmail.com", 587),
        ("imap.gmail.com", 993),
    ]
    for host, port in hosts:
        try:
            result = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ip = result[0][4][0]
            print(f"✓ {host}:{port} → {ip}")
        except Exception as e:
            print(f"✗ {host}:{port} failed: {e}")

async def test_raw_socket():
    """Test raw TCP connection (no TLS)."""
    print("\n=== Raw TCP Connection ===")
    ports = [465, 587, 25]
    for port in ports:
        try:
            print(f"\nTesting port {port}...")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("smtp.gmail.com", port),
                timeout=10
            )
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            response = data.decode('utf-8', errors='ignore')
            print(f"  ✓ Connected! Server response: {response.strip()[:80]}")
            writer.close()
            await writer.wait_closed()
        except asyncio.TimeoutError:
            print(f"  ✗ Timeout")
        except ConnectionRefusedError:
            print(f"  ✗ Connection refused (port blocked)")
        except Exception as e:
            print(f"  ✗ {type(e).__name__}: {e}")

async def test_aiosmtplib():
    """Test aiosmtplib connectivity."""
    print("\n=== aiosmtplib Connection ===")
    import aiosmtplib
    import ssl
    
    ports = [465, 587, 25]
    for port in ports:
        try:
            print(f"\nTesting port {port}...")
            use_tls = (port == 465)
            
            tls_context = ssl.create_default_context()
            client = aiosmtplib.SMTP(
                hostname="smtp.gmail.com",
                port=port,
                use_tls=use_tls,
                timeout=10,
                tls_context=tls_context
            )
            
            await asyncio.wait_for(client.connect(), timeout=15)
            print(f"  ✓ Connected")
            
            # Try STARTTLS if not implicit SSL
            if not use_tls:
                try:
                    await asyncio.wait_for(client.starttls(), timeout=15)
                    print(f"  ✓ STARTTLS successful")
                except Exception as tls_err:
                    print(f"  ✗ STARTTLS failed: {tls_err}")
            
            await client.quit()
            print(f"  ✓ Disconnected gracefully")
            
        except asyncio.TimeoutError:
            print(f"  ✗ Timeout (firewall/ISP blocking)")
        except ConnectionRefusedError:
            print(f"  ✗ Connection refused")
        except Exception as e:
            print(f"  ✗ {type(e).__name__}: {e}")

async def main():
    print("=" * 60)
    print("SMTP Diagnostic Tool")
    print("=" * 60)
    
    test_dns()
    
    await test_raw_socket()
    await test_aiosmtplib()
    
    print("\n" + "=" * 60)
    print("Summary:")
    print("  • If DNS resolution fails → Network/ISP DNS issue")
    print("  • If raw TCP fails → ISP/Firewall blocking SMTP ports")
    print("  • If aiosmtplib fails → SSL/TLS certificate issue")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
