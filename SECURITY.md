# Security Policy

## Supported Versions

The following versions of NetWatch are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Considerations

NetWatch requires **root privileges** to load eBPF programs and access kernel tracing facilities. Users should be aware of the following:

### Why root is required
- eBPF program loading (`bpf()` syscall with `BPF_PROG_LOAD`)
- Access to kernel trace events (`perf_event_open()`)
- Reading from `/sys/kernel/btf/vmlinux`

### What NetWatch does NOT do
- ❌ Does not send any data over network
- ❌ Does not write to system files outside its working directory
- ❌ Does not modify network traffic
- ❌ Does not block or filter connections (read-only monitoring)
- ❌ Does not access user files or personal data
- ❌ No telemetry or analytics

### Recommended hardening
- Run with `setcap` instead of full root (for advanced users):
  ```bash
  sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./netwatch

Review the eBPF code (netwatch.bpf.c) before running
Build from source rather than using binary releases

Reporting a Vulnerability
If you discover a security vulnerability in NetWatch, please DO NOT open a public issue.

Instead, please report it privately:

Preferred: GitHub Security Advisory
Use GitHub's private vulnerability reporting:

Go to https://github.com/wieczoj/netwatch/security/advisories/new
Fill out the security advisory form
Submit privately

Alternative: Encrypted email
For sensitive issues, contact: konradverse@gmail.com

Please include:

Description of the vulnerability
Steps to reproduce
Potential impact assessment
Any suggested fixes (optional)

Response Time
This is a personal open-source project. Response times are best-effort:

Severity	Response Time
Critical (RCE, privilege escalation)	Within 7 days
High (DoS, information disclosure)	Within 14 days
Medium/Low	Within 30 days

Disclosure Policy
I will acknowledge receipt of your report within 7 days
I will work with you to understand and validate the issue
I will release a fix as soon as possible, depending on severity
I will credit you in release notes (unless you prefer to remain anonymous)
Public disclosure will happen after a fix is released, typically with a 30-90 day embargo

Security Best Practices for Users
When using NetWatch:

Always run the latest version — security fixes are released regularly
Build from source — verify the code you're running
Verify checksums when downloading releases
Read release notes for security advisories
Use minimal privileges — prefer setcap over sudo when possible
Monitor process behavior — NetWatch should only access /sys/kernel/btf/, /sys/kernel/debug/tracing/, and /dev/dri/ (for GTK)

Known Security Considerations
Information Disclosure
NetWatch displays connection details including:

Process names and PIDs
Source and destination IP addresses
Port numbers
User IDs
If running on a shared system, this information may be sensitive. Consider running NetWatch only on systems you trust.

eBPF Program Safety
All eBPF programs in NetWatch are verified by the Linux kernel verifier before loading. This provides strong guarantees against:

Infinite loops
Out-of-bounds memory access
Invalid syscalls
However, any kernel code carries inherent risk. Review the BPF code before deploying in production environments.


Acknowledgments
We appreciate the security research community. Contributors who responsibly disclose vulnerabilities will be acknowledged in our SECURITY-HALL-OF-FAME (when applicable).

Last updated: 2026-06-12
