# Account Hijacking Prevention System

Account hijacking is a serious cybersecurity threat where attackers gain unauthorized access to user accounts using stolen or leaked credentials. Traditional password-based authentication is no longer sufficient, and even common multi-factor methods like OTP are vulnerable to attacks such as phishing, SIM swapping, and social engineering.

This project proposes a Federated Learning–based Account Hijack Prevention System integrated with a Zero Trust Adaptive Authentication framework to strengthen login security through intelligent and privacy-preserving risk analysis. The system monitors multiple login parameters such as IP address, location, device details, browser information, and login time. Using Federated Learning, the model learns suspicious behavior patterns across multiple devices without sharing raw user data, thereby maintaining user privacy while improving detection accuracy.

Each login attempt is assigned a dynamic risk score based on deviations from normal user behavior. Following Zero Trust principles, every login request is treated as untrusted. When the risk score exceeds a threshold, Adaptive Authentication is triggered, prompting the user with context-aware security questions instead of OTP verification. If verification fails or risk remains high, the login attempt is blocked and flagged as a potential hijacking incident.

By combining Federated Learning, Zero Trust security, and Adaptive Authentication, the system provides a scalable and modern solution to effectively reduce account hijacking risks.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn account_hijacking.app:app --reload --port 8000
```

### Example Request

```bash
curl -X POST http://localhost:8000/login \\
  -H \"Content-Type: application/json\" \\
  -d '{\n    \"user_id\": \"alice\",\n    \"ip_address\": \"192.168.10.55\",\n    \"latitude\": 37.7749,\n    \"longitude\": -122.4194,\n    \"device_id\": \"device-alice-1\",\n    \"browser\": \"Chrome\",\n    \"login_time\": \"2024-10-05T09:30:00Z\"\n  }'
```
