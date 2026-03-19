import json
import os

CWE_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cwe_corpus.json")

_cwe_cache: list[dict] | None = None


def _load_corpus() -> list[dict]:
    global _cwe_cache
    if _cwe_cache is not None:
        return _cwe_cache

    if os.path.exists(CWE_DATA_PATH):
        with open(CWE_DATA_PATH, "r") as f:
            _cwe_cache = json.load(f)
    else:
        _cwe_cache = _get_fallback_corpus()

    return _cwe_cache


def search(query: str) -> list[dict]:
    corpus = _load_corpus()
    query_lower = query.lower()
    results = []

    for entry in corpus:
        score = 0
        if query_lower in entry.get("name", "").lower():
            score += 10
        if query_lower in entry.get("description", "").lower():
            score += 5
        for kw in query_lower.split():
            if kw in entry.get("name", "").lower():
                score += 3
            if kw in entry.get("description", "").lower():
                score += 1
        if score > 0:
            results.append((score, entry))

    results.sort(key=lambda x: -x[0])
    return [r[1] for r in results[:5]]


def lookup(cwe_id: str) -> dict | None:
    corpus = _load_corpus()
    cwe_id_clean = cwe_id.upper().replace("CWE-", "")
    for entry in corpus:
        if entry.get("cwe_id", "").replace("CWE-", "") == cwe_id_clean:
            return entry
    return None


async def cwe_lookup_tool(query: str = "", cwe_id: str = "") -> dict:
    if cwe_id:
        result = lookup(cwe_id)
        if result:
            return result
        return {"error": f"CWE {cwe_id} not found"}

    if query:
        results = search(query)
        if results:
            return {"results": results}
        return {"error": f"No CWE entries found for query: {query}"}

    return {"error": "Provide either query or cwe_id"}


def _get_fallback_corpus() -> list[dict]:
    return [
        {
            "cwe_id": "CWE-79",
            "name": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            "severity": "HIGH",
            "common_consequences": ["Execute unauthorized code or commands", "Read application data", "Modify application data"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis", "Manual Review"],
            "mitigations": ["Input validation", "Output encoding", "Content Security Policy"],
            "related_cwes": ["CWE-80", "CWE-81", "CWE-83", "CWE-87"],
        },
        {
            "cwe_id": "CWE-89",
            "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
            "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
            "severity": "CRITICAL",
            "common_consequences": ["Read application data", "Modify application data", "Bypass protection mechanism"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis", "Manual Review"],
            "mitigations": ["Use parameterized queries", "Use stored procedures", "Input validation", "Use an ORM"],
            "related_cwes": ["CWE-564", "CWE-943"],
        },
        {
            "cwe_id": "CWE-78",
            "name": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
            "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
            "severity": "CRITICAL",
            "common_consequences": ["Execute unauthorized code or commands", "Read/modify files", "DoS"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Input validation", "Use library calls instead of external processes", "Escape shell metacharacters"],
            "related_cwes": ["CWE-77", "CWE-88"],
        },
        {
            "cwe_id": "CWE-22",
            "name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
            "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
            "severity": "HIGH",
            "common_consequences": ["Read files or directories", "Modify files or directories"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis"],
            "mitigations": ["Input validation", "Canonicalize paths", "Use a chroot jail"],
            "related_cwes": ["CWE-23", "CWE-36"],
        },
        {
            "cwe_id": "CWE-352",
            "name": "Cross-Site Request Forgery (CSRF)",
            "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
            "severity": "HIGH",
            "common_consequences": ["Gain privileges / assume identity", "Modify application data"],
            "detection_methods": ["Manual Review", "Automated Static Analysis"],
            "mitigations": ["Anti-CSRF tokens", "SameSite cookie attribute", "Check Referer header"],
            "related_cwes": ["CWE-346"],
        },
        {
            "cwe_id": "CWE-502",
            "name": "Deserialization of Untrusted Data",
            "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
            "severity": "CRITICAL",
            "common_consequences": ["Execute unauthorized code or commands", "DoS"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Avoid native deserialization", "Use safe serialization formats (JSON)", "Integrity checks"],
            "related_cwes": ["CWE-913"],
        },
        {
            "cwe_id": "CWE-918",
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
            "severity": "HIGH",
            "common_consequences": ["Read application data", "Bypass access controls", "Scan internal networks"],
            "detection_methods": ["Manual Review", "Dynamic Analysis"],
            "mitigations": ["Allow-list of URLs/domains", "Block private IP ranges", "Use a proxy"],
            "related_cwes": ["CWE-441"],
        },
        {
            "cwe_id": "CWE-287",
            "name": "Improper Authentication",
            "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
            "severity": "CRITICAL",
            "common_consequences": ["Gain privileges / assume identity", "Read/modify application data"],
            "detection_methods": ["Automated Static Analysis", "Manual Review", "Penetration Testing"],
            "mitigations": ["Multi-factor authentication", "Secure session management", "Strong password policies"],
            "related_cwes": ["CWE-306", "CWE-384"],
        },
        {
            "cwe_id": "CWE-862",
            "name": "Missing Authorization",
            "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
            "severity": "HIGH",
            "common_consequences": ["Gain privileges", "Read/modify data"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Enforce authorization checks", "Principle of least privilege", "Role-based access control"],
            "related_cwes": ["CWE-863", "CWE-285"],
        },
        {
            "cwe_id": "CWE-798",
            "name": "Use of Hard-coded Credentials",
            "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
            "severity": "CRITICAL",
            "common_consequences": ["Gain privileges / assume identity", "Bypass protection mechanism"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Store credentials outside of code", "Use environment variables", "Use secret management systems"],
            "related_cwes": ["CWE-259", "CWE-321"],
        },
        {
            "cwe_id": "CWE-200",
            "name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
            "severity": "MEDIUM",
            "common_consequences": ["Read application data", "Read sensitive information"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Minimize information exposure", "Access control", "Error handling without detail leaks"],
            "related_cwes": ["CWE-209", "CWE-532"],
        },
        {
            "cwe_id": "CWE-434",
            "name": "Unrestricted Upload of File with Dangerous Type",
            "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
            "severity": "CRITICAL",
            "common_consequences": ["Execute unauthorized code or commands"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis"],
            "mitigations": ["Validate file type", "Store uploads outside webroot", "Rename uploaded files"],
            "related_cwes": ["CWE-351", "CWE-436"],
        },
        {
            "cwe_id": "CWE-611",
            "name": "Improper Restriction of XML External Entity Reference",
            "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
            "severity": "HIGH",
            "common_consequences": ["Read files", "SSRF", "DoS"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis"],
            "mitigations": ["Disable DTDs", "Disable external entities", "Use less complex data formats"],
            "related_cwes": ["CWE-776"],
        },
        {
            "cwe_id": "CWE-327",
            "name": "Use of a Broken or Risky Cryptographic Algorithm",
            "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
            "severity": "HIGH",
            "common_consequences": ["Read application data", "Bypass protection mechanism"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Use well-known, strong cryptographic algorithms", "Use proper key lengths", "Keep libraries updated"],
            "related_cwes": ["CWE-326", "CWE-328"],
        },
        {
            "cwe_id": "CWE-601",
            "name": "URL Redirection to Untrusted Site (Open Redirect)",
            "description": "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.",
            "severity": "MEDIUM",
            "common_consequences": ["Phishing attacks", "Credential theft"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis"],
            "mitigations": ["Allow-list of redirect targets", "Validate URL scheme and domain"],
            "related_cwes": ["CWE-698"],
        },
        {
            "cwe_id": "CWE-77",
            "name": "Improper Neutralization of Special Elements used in a Command (Command Injection)",
            "description": "The software constructs all or part of a command using externally-influenced input, but does not neutralize special elements that could modify the intended command.",
            "severity": "CRITICAL",
            "common_consequences": ["Execute unauthorized commands", "Read/modify data"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Use parameterized interfaces", "Input validation", "Least privilege"],
            "related_cwes": ["CWE-78", "CWE-88", "CWE-917"],
        },
        {
            "cwe_id": "CWE-269",
            "name": "Improper Privilege Management",
            "description": "The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control.",
            "severity": "HIGH",
            "common_consequences": ["Gain privileges", "Execute unauthorized code"],
            "detection_methods": ["Manual Review", "Architecture Review"],
            "mitigations": ["Principle of least privilege", "Separation of duties", "Role-based access control"],
            "related_cwes": ["CWE-250", "CWE-732"],
        },
        {
            "cwe_id": "CWE-522",
            "name": "Insufficiently Protected Credentials",
            "description": "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.",
            "severity": "HIGH",
            "common_consequences": ["Gain privileges / assume identity"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Use secure hashing for passwords (bcrypt, argon2)", "Use TLS for transmission", "Never log credentials"],
            "related_cwes": ["CWE-256", "CWE-523"],
        },
        {
            "cwe_id": "CWE-732",
            "name": "Incorrect Permission Assignment for Critical Resource",
            "description": "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.",
            "severity": "HIGH",
            "common_consequences": ["Read/modify critical resources", "Gain privileges"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Follow principle of least privilege", "Set restrictive default permissions"],
            "related_cwes": ["CWE-276", "CWE-285"],
        },
        {
            "cwe_id": "CWE-384",
            "name": "Session Fixation",
            "description": "Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.",
            "severity": "HIGH",
            "common_consequences": ["Session hijacking", "Assume identity"],
            "detection_methods": ["Manual Review", "Dynamic Analysis"],
            "mitigations": ["Regenerate session ID after login", "Use framework session management"],
            "related_cwes": ["CWE-287", "CWE-613"],
        },
        {
            "cwe_id": "CWE-943",
            "name": "Improper Neutralization of Special Elements in Data Query Logic",
            "description": "The application generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.",
            "severity": "HIGH",
            "common_consequences": ["Read/modify data", "Bypass authentication"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Parameterized queries", "Input validation", "ORM usage"],
            "related_cwes": ["CWE-89", "CWE-90", "CWE-564"],
        },
        {
            "cwe_id": "CWE-564",
            "name": "SQL Injection: Hibernate",
            "description": "Using Hibernate to execute a dynamic SQL statement built with user-controlled input can allow an attacker to modify the statement's meaning or to execute arbitrary SQL commands.",
            "severity": "HIGH",
            "common_consequences": ["Read/modify data", "Execute unauthorized queries"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Use Hibernate's parameterized HQL queries", "Input validation"],
            "related_cwes": ["CWE-89", "CWE-943"],
        },
        {
            "cwe_id": "CWE-94",
            "name": "Improper Control of Generation of Code (Code Injection)",
            "description": "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
            "severity": "CRITICAL",
            "common_consequences": ["Execute unauthorized code"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Avoid dynamic code generation from user input", "Input validation", "Sandboxing"],
            "related_cwes": ["CWE-95", "CWE-96"],
        },
        {
            "cwe_id": "CWE-1321",
            "name": "Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)",
            "description": "The software receives input from an upstream component that specifies attributes that are to be initialized or updated in an object, but it does not properly control modifications of attributes of the object prototype.",
            "severity": "HIGH",
            "common_consequences": ["Modify application behavior", "Execute code", "DoS"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Freeze prototypes", "Use Map instead of plain objects", "Input validation"],
            "related_cwes": ["CWE-915"],
        },
        {
            "cwe_id": "CWE-613",
            "name": "Insufficient Session Expiration",
            "description": "The software does not sufficiently expire session tokens, allowing attackers to use old session credentials.",
            "severity": "MEDIUM",
            "common_consequences": ["Session hijacking", "Assume identity"],
            "detection_methods": ["Manual Review", "Architecture Review"],
            "mitigations": ["Set session timeouts", "Invalidate sessions on logout", "Implement idle timeouts"],
            "related_cwes": ["CWE-384", "CWE-287"],
        },
        {
            "cwe_id": "CWE-209",
            "name": "Generation of Error Message Containing Sensitive Information",
            "description": "The software generates an error message that includes sensitive information about its environment, users, or associated data.",
            "severity": "MEDIUM",
            "common_consequences": ["Information disclosure"],
            "detection_methods": ["Automated Static Analysis", "Dynamic Analysis"],
            "mitigations": ["Generic error messages for users", "Detailed errors only in logs", "Custom error pages"],
            "related_cwes": ["CWE-200", "CWE-532"],
        },
        {
            "cwe_id": "CWE-532",
            "name": "Insertion of Sensitive Information into Log File",
            "description": "Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.",
            "severity": "MEDIUM",
            "common_consequences": ["Information disclosure"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Sanitize log output", "Never log credentials or PII", "Protect log files"],
            "related_cwes": ["CWE-200", "CWE-209"],
        },
        {
            "cwe_id": "CWE-330",
            "name": "Use of Insufficiently Random Values",
            "description": "The software uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.",
            "severity": "HIGH",
            "common_consequences": ["Bypass protection mechanism", "Predict security tokens"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Use cryptographically secure random number generators", "os.urandom / secrets module"],
            "related_cwes": ["CWE-331", "CWE-338"],
        },
        {
            "cwe_id": "CWE-306",
            "name": "Missing Authentication for Critical Function",
            "description": "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
            "severity": "CRITICAL",
            "common_consequences": ["Gain privileges", "Access protected resources"],
            "detection_methods": ["Manual Review", "Architecture Review"],
            "mitigations": ["Require authentication for all sensitive endpoints", "Defense in depth"],
            "related_cwes": ["CWE-287", "CWE-862"],
        },
        {
            "cwe_id": "CWE-312",
            "name": "Cleartext Storage of Sensitive Information",
            "description": "The application stores sensitive information in cleartext within a resource that might be accessible to another control sphere.",
            "severity": "HIGH",
            "common_consequences": ["Read sensitive information"],
            "detection_methods": ["Automated Static Analysis", "Manual Review"],
            "mitigations": ["Encrypt sensitive data at rest", "Use secure key management"],
            "related_cwes": ["CWE-311", "CWE-319"],
        },
    ]
