# BioZero VM Baseline Report
Snapshot: snapshot-0-clean-install

## Purpose
This VM serves as the controlled baseline environment for the BioZero Zero-Trust Lab.
All future changes will be tracked via snapshots and documentation.

## Host Environment
- Host OS: Pop!_OS
- Hypervisor: KVM / libvirt
- VM created via: virt-install (CLI)
- Rationale: reproducibility, automation, portability

## VM Configuration
- OS: Ubuntu Server 22.04 LTS
- vCPUs: 2
- RAM: 4096 MB
- Disk: qcow2 (virtio)
- Boot mode: UEFI
- Network: default NAT (virtio)
- Memory: 30G

## Storage Layout
- Disk: LVM enabled
- Encryption: (yes/no — document your choice)
- Reasoning: balance between flexibility and security baseline

## Access
- OpenSSH: Installed during setup
- Reason: enables remote management and later hardening steps

## Snapshot Strategy
- snapshot-0-clean-install
  - Description: pristine OS state before hardening
  - Purpose: rollback anchor, migration comparison point

## Validation
- VM boots successfully
- Snapshot verified via `virsh snapshot-list`

## Additional Notes:
- I created a quick .txt file called ACWasHere.txt it contains a
line of text and a timestamp. 

## Next Planned Actions
- Apply baseline hardening
- Install security tooling
- Create snapshot-1-hardened
