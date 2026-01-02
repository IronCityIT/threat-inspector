"""
AI-powered remediation guidance generation.
Supports local models (transformers), Ollama, and cloud APIs.
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class RemediationResult:
    """Result of remediation generation."""
    guidance: str
    source: str  # "local", "ollama", "openai", "anthropic", "static"
    confidence: float = 1.0


# Static remediation guidance for common vulnerabilities
STATIC_REMEDIATION = {
    "sql injection": """
**Remediation Steps:**
1. Use parameterized queries or prepared statements for all database interactions
2. Implement input validation using allowlists for expected data formats
3. Apply the principle of least privilege for database accounts
4. Enable proper error handling to avoid exposing database details
5. Consider using an ORM (Object-Relational Mapping) framework
6. Implement Web Application Firewall (WAF) rules for SQL injection patterns
""",
    
    "cross-site scripting": """
**Remediation Steps:**
1. Encode all output based on context (HTML, JavaScript, URL, CSS)
2. Implement Content Security Policy (CSP) headers
3. Use HTTPOnly and Secure flags for cookies
4. Validate and sanitize all user input on the server side
5. Use modern frameworks with built-in XSS protection
6. Implement input length limits where appropriate
""",
    
    "xss": """
**Remediation Steps:**
1. Encode all output based on context (HTML, JavaScript, URL, CSS)
2. Implement Content Security Policy (CSP) headers
3. Use HTTPOnly and Secure flags for cookies
4. Validate and sanitize all user input on the server side
5. Use modern frameworks with built-in XSS protection
""",
    
    "ssl": """
**Remediation Steps:**
1. Upgrade to TLS 1.2 or TLS 1.3 (disable SSLv2, SSLv3, TLS 1.0, TLS 1.1)
2. Use strong cipher suites (AES-GCM, ChaCha20-Poly1305)
3. Implement HSTS (HTTP Strict Transport Security)
4. Ensure valid, non-expired certificates from trusted CAs
5. Enable OCSP stapling for certificate validation
6. Disable compression (CRIME/BREACH attacks)
""",
    
    "certificate": """
**Remediation Steps:**
1. Renew expired certificates before expiration
2. Use certificates from trusted Certificate Authorities
3. Implement certificate monitoring and alerting
4. Enable OCSP stapling
5. Consider Certificate Transparency logging
6. Use appropriate key sizes (RSA 2048+ or ECDSA 256+)
""",
    
    "outdated": """
**Remediation Steps:**
1. Update the affected software to the latest stable version
2. Implement a patch management process with defined SLAs
3. Subscribe to security advisories for critical software
4. Test updates in staging environment before production deployment
5. Consider automated update mechanisms where appropriate
6. Maintain an inventory of software versions in use
""",
    
    "missing security header": """
**Remediation Steps:**
1. Implement Content-Security-Policy (CSP) header
2. Add X-Content-Type-Options: nosniff
3. Add X-Frame-Options: DENY or SAMEORIGIN
4. Add X-XSS-Protection: 1; mode=block
5. Implement Strict-Transport-Security (HSTS)
6. Add Referrer-Policy header
7. Consider Permissions-Policy for feature restrictions
""",
    
    "weak password": """
**Remediation Steps:**
1. Enforce minimum password length (12+ characters recommended)
2. Require complexity (uppercase, lowercase, numbers, symbols)
3. Implement account lockout after failed attempts
4. Use secure password hashing (bcrypt, Argon2, PBKDF2)
5. Check passwords against known breached password lists
6. Implement multi-factor authentication (MFA)
""",
    
    "information disclosure": """
**Remediation Steps:**
1. Remove sensitive information from error messages
2. Disable detailed error pages in production
3. Remove server version headers
4. Implement proper access controls
5. Review and sanitize API responses
6. Remove comments containing sensitive information from code
""",
    
    "directory listing": """
**Remediation Steps:**
1. Disable directory listing in web server configuration
2. Add index files to all directories
3. Review web server configuration for security
4. Implement proper access controls
5. Remove unnecessary files and directories
""",
    
    "default credentials": """
**Remediation Steps:**
1. Change all default passwords immediately
2. Implement strong password policy
3. Remove or disable default accounts
4. Audit all systems for default credentials
5. Implement credential management procedures
6. Use unique credentials for each system
""",
    
    "csrf": """
**Remediation Steps:**
1. Implement anti-CSRF tokens on all state-changing forms
2. Verify the Origin and Referer headers
3. Use SameSite cookie attribute
4. Require re-authentication for sensitive actions
5. Use framework-provided CSRF protection mechanisms
""",
    
    "open redirect": """
**Remediation Steps:**
1. Avoid using user input for redirect destinations
2. If redirects are necessary, use allowlists for valid destinations
3. Validate redirect URLs are relative or to known-good domains
4. Warn users before redirecting to external sites
5. Use indirect reference maps instead of direct URLs
""",
}


def get_static_remediation(vulnerability_title: str) -> Optional[str]:
    """Get static remediation guidance based on vulnerability title."""
    title_lower = vulnerability_title.lower()
    
    for keyword, guidance in STATIC_REMEDIATION.items():
        if keyword in title_lower:
            return guidance.strip()
    
    return None


def generate_remediation(
    title: str,
    description: str = "",
    cve_id: str = "",
    severity: str = "",
    asset_type: str = "",
    existing_solution: str = "",
) -> RemediationResult:
    """
    Generate remediation guidance for a vulnerability.
    
    Args:
        title: Vulnerability title
        description: Vulnerability description
        cve_id: CVE identifier if available
        severity: Vulnerability severity
        asset_type: Type of affected asset
        existing_solution: Existing solution from scanner
        
    Returns:
        RemediationResult with guidance and metadata
    """
    # First check if scanner provided a solution
    if existing_solution and len(existing_solution) > 50:
        return RemediationResult(
            guidance=existing_solution,
            source="scanner",
            confidence=0.9,
        )
    
    # Try static remediation
    static = get_static_remediation(title)
    if static:
        return RemediationResult(
            guidance=static,
            source="static",
            confidence=0.8,
        )
    
    # Try AI-based remediation
    try:
        from threat_inspector.config import settings
        engine = settings.remediation.engine.lower()
        
        if engine == "ollama":
            result = _generate_ollama(title, description, cve_id, severity)
            if result:
                return result
        
        elif engine == "local":
            result = _generate_local(title, description, cve_id, severity)
            if result:
                return result
    except Exception:
        pass
    
    # Fallback to generic guidance
    return RemediationResult(
        guidance=_generate_generic_guidance(title, severity),
        source="generic",
        confidence=0.5,
    )


def _build_prompt(title: str, description: str, cve_id: str, severity: str) -> str:
    """Build a prompt for AI remediation generation."""
    prompt = f"""You are a cybersecurity expert. Provide specific, actionable remediation steps for the following vulnerability.

Vulnerability: {title}
Severity: {severity}
"""
    if cve_id:
        prompt += f"CVE: {cve_id}\n"
    if description:
        prompt += f"Description: {description[:500]}\n"
    
    prompt += """
Provide 5-7 specific remediation steps. Be concise and actionable.
Format as numbered steps.
"""
    return prompt


def _generate_ollama(
    title: str, description: str, cve_id: str, severity: str
) -> Optional[RemediationResult]:
    """Generate remediation using Ollama."""
    try:
        import ollama
        from threat_inspector.config import settings
        
        prompt = _build_prompt(title, description, cve_id, severity)
        
        response = ollama.chat(
            model=settings.remediation.ollama_model,
            messages=[{"role": "user", "content": prompt}],
        )
        
        guidance = response["message"]["content"]
        
        return RemediationResult(
            guidance=guidance,
            source="ollama",
            confidence=0.85,
        )
    except Exception:
        return None


def _generate_local(
    title: str, description: str, cve_id: str, severity: str
) -> Optional[RemediationResult]:
    """Generate remediation using local transformers model."""
    try:
        from transformers import pipeline
        
        # Use a small model for quick generation
        generator = pipeline("text-generation", model="gpt2", max_length=200)
        
        prompt = f"Security remediation for {title}: "
        result = generator(prompt, num_return_sequences=1)
        
        guidance = result[0]["generated_text"]
        
        return RemediationResult(
            guidance=guidance,
            source="local",
            confidence=0.6,
        )
    except Exception:
        return None


def _generate_generic_guidance(title: str, severity: str) -> str:
    """Generate generic remediation guidance."""
    severity_actions = {
        "critical": "Immediate action required. ",
        "high": "Prioritize remediation within 7 days. ",
        "medium": "Address within 30 days. ",
        "low": "Address in next maintenance window. ",
        "info": "Review and assess risk. ",
    }
    
    urgency = severity_actions.get(severity.lower(), "")
    
    return f"""{urgency}

**General Remediation Steps for: {title}**

1. Research the specific vulnerability and its attack vectors
2. Identify all affected systems and components
3. Review vendor advisories and patches
4. Test remediation in a non-production environment
5. Apply patches or configuration changes
6. Verify the vulnerability is resolved through rescanning
7. Document the remediation actions taken

**Additional Resources:**
- Check CVE databases for specific vulnerability details
- Review OWASP guidelines for web application vulnerabilities
- Consult vendor documentation for product-specific fixes
"""
