# BioZero Sustainment Lab  
## Snapshot Documentation – Pre-Hardening & SSH Baseline

---

## System Context

- **Project:** BioZero – Integrated Bio-Cyber Defense Lab  
- **Host OS:** Pop!_OS (libvirt / KVM)  
- **Guest VM:** `biozero-ubuntu`  
- **Guest OS:** Ubuntu Server 22.04 LTS  
- **Access Model:** Non-root administrative user (`nonrootadminuser`) with controlled privilege escalation  
- **Snapshot Method:** `virsh snapshot-create-as` (internal metadata snapshots)

---

## Snapshot 1: Pre-Hardening Baseline

**Snapshot Name:** `snapshot-1-pre-hardening`

### Purpose

This snapshot represents the **clean system baseline** immediately after:

- Successful Ubuntu Server 22.04 installation  
- Creation of a non-root administrative user  
- Verification of system boot, login, and core service stability  
- No security hardening applied yet (SSH, firewall, logging)

### Engineering Rationale

This snapshot exists to:

- Establish a **known-good rollback point**
- Preserve system state *before* any security controls are introduced
- Enable precise attribution of changes during later testing
- Support sustainment, auditability, and controlled configuration management

This snapshot serves as the **parent baseline** for all subsequent security hardening stages.

---

## Snapshot 2: Post-SSH / Pre-Firewall Baseline

**Snapshot Name:** `snapshot-1.2-pre-hardening`

### Purpose

This snapshot captures the system state **after SSH baseline hardening** but **before** firewall (UFW) and logging controls are applied.

### Changes Included

- SSH service enabled and running
- Root SSH login disabled
- SSH access restricted to `nonrootadminuser`
- Authentication controls tuned (login grace time, max attempts)
- SSH configuration validated using `sshd -t`
- SSH service restarted safely
- Local SSH connectivity tested successfully

### What This Snapshot Demonstrates

- Secure remote access without loss of availability
- Proper sequencing of configuration changes:
  - Edit → validate → restart → test
- Defensive-first approach: access control before network restriction
- Safe rollback point before introducing firewall rules that could affect connectivity

---

## Snapshot Strategy Summary

| Snapshot Name | Lifecycle Role | Value |
|--------------|----------------|-------|
| `snapshot-1-pre-hardening` | Clean baseline | Full rollback to known-good state |
| `snapshot-1.2-pre-hardening` | Post-SSH checkpoint | Isolates SSH hardening from firewall/logging changes |

This strategy supports:

- Change control
- Troubleshooting isolation
- Evidence-based validation
- Demonstrable sustainment engineering discipline

---

## Tooling Notes

Observed `virt-viewer` GLib warnings related to desktop width/height are **non-impacting UI warnings** and do **not** affect:

- VM integrity
- Snapshot consistency
- SSH configuration
- System security posture

No remediation was required.

---

## Current Project Status

- ✅ Ubuntu Server installed and validated  
- ✅ Non-root administrative access established  
- ✅ SSH baseline hardened and tested  
- ✅ Pre- and post-SSH snapshots captured  

---

## Next Planned Phase

**Firewall Baseline (UFW)**

Planned actions include:

- Define and apply minimal firewall rules
- Validate SSH access post-firewall
- Capture next snapshot (`snapshot-2-firewall-baseline`)
- Update change log and evidence log

---

*Document maintained as part of BioZero Sustainment & Validation workflow.*

