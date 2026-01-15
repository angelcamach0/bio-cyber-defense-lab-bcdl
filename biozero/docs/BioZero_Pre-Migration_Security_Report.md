# BioZero Sustainment Lab – Pre‑Migration Security Report

## Document Purpose
This document records the **completion of local hardening phases prior to migration to Proxmox**.  
It serves as a checkpoint artifact demonstrating controlled system build‑up, verification, and snapshot discipline consistent with sustainment cybersecurity and test/validation practices.

---

## Environment Overview
- **Host Hypervisor:** QEMU/KVM (libvirt)
- **Host OS:** Pop!_OS
- **Guest OS:** Ubuntu Server 22.04.5 LTS
- **VM Name:** `biozero-ubuntu`
- **Primary Admin User:** `nonrootadminuser`
- **Root Access:** Disabled for direct login; privilege escalation via sudo only

---

## Completed Phases (Local KVM)

### Phase 0 – Clean Installation
- Fresh Ubuntu Server install
- Default services only
- No hardening applied

**Snapshot:**  
- `snapshot-0-clean-install`

---

### Phase 1 – Pre‑Hardening Baseline
- Created non‑root administrative user
- Verified sudo access
- Verified no direct root login

**Snapshot:**  
- `snapshot-1-pre-hardening`

---

### Phase 2 – SSH Baseline
- SSH service validated and running
- Root login disabled
- Explicit user allow‑list configured
- Configuration validated prior to restart
- SSH access tested locally

**Snapshot:**  
- `snapshot-1.2-pre-hardening`

---

### Phase 3 – Firewall Baseline (UFW)
- Default deny (incoming)
- Default allow (outgoing)
- SSH explicitly permitted
- Firewall enabled and validated
- Connectivity verified post‑enable

**Snapshot:**  
- `snapshot-2-firewall-baseline`

---

### Phase 4 – Logging & Audit Groundwork
#### systemd‑journald
- Persistent journal enabled
- Disk usage validated
- Service state verified

#### Audit Framework
- `auditd` installed and enabled
- Minimal audit rules applied:
  - SSH configuration changes
  - Sudoers modifications
  - Authentication logs
  - Audit log integrity
- Rules loaded and verified

**Snapshots:**  
- `snapshot-3-logging-baseline`  
- `snapshot-4-audit-baseline`

---

## Snapshot Discipline Summary
All snapshots were taken:
- With the VM in a **known, stable state**
- After validation of each control
- With descriptive, auditable naming

This establishes a **clean rollback chain** and clear evidence trail.

---

## Migration Status
🚫 **Migration to Proxmox has NOT occurred yet**

This VM is now classified as:
> **Migration‑Ready Gold Image (Local KVM)**

Migration will occur as a **dedicated phase** to:
- Preserve attribution of changes
- Validate security posture across hypervisor boundaries
- Produce Proxmox‑native validation snapshots

---

## Next Planned Phase
**Phase 5 – Privilege & Abuse Resistance**
- sudo policy tightening
- session hardening
- command accountability

A snapshot will be taken **before migration** once Phase 5 is complete.

---

## Interview‑Relevant Takeaway
This document demonstrates:
- Controlled system lifecycle
- Change accountability
- Snapshot‑driven validation
- Separation of hardening vs. migration risk

Exactly aligned with sustainment cybersecurity test and validation methodology.
