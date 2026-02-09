# DNS setup for newbackend

1. **Point the domain to your server (DNS)**  
   In your domain provider's DNS panel:
- **Type:** A  
- **Host:** (e.g. `newbackend` or `final`)  
- **Value:** YOUR_SERVER_PUBLIC_IP  
- **TTL:** Auto  

Then use HTTPS (e.g. Let's Encrypt) for the domain.
