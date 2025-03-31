from dns import resolver
try:
    ip_answer = resolver.resolve("modaexperts.com", 'A')  # Replace with your test domain
    print(f"Resolved IP: {ip_answer[0].to_text()}")
except Exception as e:
    print(f"Error: {e}")
