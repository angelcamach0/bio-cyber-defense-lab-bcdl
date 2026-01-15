# GitHub Upload Guide (What to Include / Exclude)

## Do NOT upload
Sensitive or large artifacts should stay local:
- VM images: `*.qcow2`, `*.vmdk`, `*.ova`
- PKI private keys and cert bundles: `biozero/infra/PKI/pki/`
- Runtime data and evidence logs (if public): `biozero/docs/evidence/`, `biozero/**/data/`
- Docker volumes or local caches
- Local notes or outputs like `output.txt`
- Environment and secret files: `.env`, `.env.*`, `.secrets/`
- Pipeline outputs or tmp folders (fastp outputs, VCFs, cached artifacts)

## Safe to upload
- Source code under `biozero/services/`, `biozero/bio/`, `biozero/simulated-adversary/`
- Documentation in `biozero/docs/` (excluding evidence)
- Infrastructure files in `biozero/infra/` (excluding generated certs)

## Suggested .gitignore
Add or update `.gitignore` with:
```
# VM images
*.qcow2
*.vmdk
*.ova

# PKI artifacts
biozero/infra/PKI/pki/

# Runtime data and evidence
biozero/docs/evidence/
biozero/**/data/

# Local logs and outputs
output.txt
biozero/infra/compose/output*.txt
biozero/infra/compose/*.log
.env
.env.*
.secrets/
biozero/infra/compose/.env
biozero/infra/compose/.secrets/
biozero/infra/compose/*cache*/
biozero/infra/compose/*tmp*/
biozero/**/tmp/
biozero/**/cache/
biozero/**/outputs/
biozero/**/build/
biozero/**/.DS_Store
biozero/**/node_modules/
biozero/**/__pycache__/
biozero/**/*.pyc
biozero/**/*.pyo
biozero/**/*.pyd
```

## Example commands (first push)
```bash
cd "Bio-Cyber Defense Lab (BCDL)"

git init
git add .

git rm -r --cached biozero/infra/PKI/pki biozero/docs/evidence || true

git commit -m "Initial BioZero MVP"

git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

## Example commands (update .gitignore)
```bash
cd "Bio-Cyber Defense Lab (BCDL)"

echo "biozero/infra/PKI/pki/" >> .gitignore
echo "biozero/docs/evidence/" >> .gitignore

echo "biozero/**/data/" >> .gitignore

echo "*.qcow2" >> .gitignore
```
