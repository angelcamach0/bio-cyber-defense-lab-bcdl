# BioZero Project – VM Privilege Model Incident Report

## Document ID
BZ-VM-SEC-002

## Date
2026-01-07

## System Context
- **Host OS:** Pop!_OS (KVM/libvirt)
- **Guest OS:** Ubuntu Server 22.04 LTS
- **VM Name:** biozero-ubuntu
- **Hypervisor:** KVM/QEMU via libvirt
- **Project:** BioZero – Zero Trust Lab

---

## Purpose
This report documents a user privilege escalation issue encountered during the initial Ubuntu Server VM setup, the root cause, corrective actions taken, and the resulting hardened privilege model. This serves as evidence of secure system administration practices aligned with least-privilege and auditability principles.

---

## Incident Summary
During post-installation validation, the primary administrative user (`nonrootadminuser`) was unable to execute privileged commands using `sudo`. Attempts to elevate privileges resulted in the following error:

> `nonrootadminuser is not in the sudoers file. This incident will be reported.`

Additionally, direct root access attempts using `su` and `su -` failed with authentication errors.

---

## Observed Symptoms
- `sudo whoami` failed for `nonrootadminuser`
- `su` / `su root` returned authentication failure
- Root shell accessible only via recovery environment

---

## Root Cause Analysis
- During Ubuntu Server installation, the user account `nonrootadminuser` was created **without membership in the `sudo` group**.
- Ubuntu disables direct root login by default (root account locked), which prevented recovery via `su`.
- This behavior is **expected by design** on Ubuntu systems and aligns with secure defaults.

---

## Corrective Actions Taken

### Recovery Access
- Booted into **Recovery Mode**
- Dropped to **root shell prompt** (read-only filesystem initially)

### Privilege Fix
Executed the following command:

```bash
usermod -aG sudo nonrootadminuser
```

### Verification
```bash
groups nonrootadminuser
```

Result:
```
nonrootadminuser : nonrootadminuser sudo
```

System rebooted into normal mode.

---

## Post-Fix Validation

```bash
sudo whoami
```

Output:
```
root
```

This confirms controlled privilege escalation is functioning correctly.

---

## Final Privilege Model (Hardened State)

| Access Type | Status |
|------------|--------|
| Default login | nonrootadminuser |
| Direct root login | Disabled |
| Root shell via su | Blocked |
| Privilege escalation | sudo only |
| Auditability | Enabled |

---

## Security Rationale
This configuration enforces:
- **Least privilege** (no default root sessions)
- **Reduced blast radius** for compromised accounts
- **Audit-friendly administration** via sudo logs

This aligns with:
- CIS Linux Benchmarks
- CMMC Level 1–2 principles
- Real-world enterprise Linux administration standards

---

## Project Relevance (BioZero)
This incident and resolution demonstrate:
- Secure baseline VM provisioning
- Administrative access control
- Operational troubleshooting under constrained access
- Change documentation and traceability

This report should be referenced in:
- `docs/incidents_and_troubleshooting.md`
- `docs/evidence_log.md`

---

## Snapshot Reference
**Snapshot Name:** `snapshot-0-clean-install`

This snapshot captures the system **after** privilege correction and represents the first hardened baseline for the BioZero VM lifecycle.

---

## Status
✅ Resolved

---

## Notes
The chosen username (`nonrootadminuser`) was intentional to reinforce role clarity and discourage habitual root usage. This naming choice supports long-term maintainability and security awareness.

