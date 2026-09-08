# MVP Threat Model

### Untrusted input
Every APK is treated as hostile bytes. It is never installed or executed.

### Main risks
- zip/decompression bombs
- oversized uploads
- malformed APKs exploiting parser bugs
- path traversal through filenames
- resource exhaustion
- denial of service through expensive analysis
- malicious metadata/URLs rendered in the UI

### Mitigations
- upload size limit
- generated storage filenames
- SHA-256 before analysis
- parser exceptions converted to safe failure states
- timeouts/resource limits are required for production worker deployment
- HTML escaping via React rendering
- no direct shell execution of APK contents
- no raw exception returned to clients

### Production requirement
Parser isolation is strongly recommended. Androguard itself must not be treated as a security boundary.
