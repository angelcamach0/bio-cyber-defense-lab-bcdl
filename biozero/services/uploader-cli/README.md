# Uploader CLI

Select the protocol as the first argument. The Linux `owner-v1` path retains
private client history and stops at an upload-service transport acknowledgement.
It does not start protected analysis or poll the legacy results API.

```sh
go build -trimpath -buildvcs=false -o /absolute/private/uploader .
/absolute/private/uploader --protocol owner-v1 \
  --config /absolute/private/client.json \
  --run-dir /absolute/private/new-run \
  --action submit --file /absolute/private/sample.fastq
```

The configuration, input and pinned assets must be current-user, single-link
regular files with mode0600; the new run root has mode0700. All ancestors are
opened without following symlinks. Keep credentials and run history private.

The closed schema1 configuration requires `authority_url`,
`authority_server_name`, `upload_url`, `upload_server_name`, `tls_certificate`,
`tls_private_key`, `authority_ca`, `upload_ca`, `encryption_public_key`,
`authority_id`, `public_key_hex`, `pipeline_mode`, `execution_profile_sha256`,
`expected_scope` and `original_name`. Each asset is `{path, sha256}`. URLs are
HTTPS origins; the client chooses the fixed protocol routes. The worker encryption
public key is separate from the client's mTLS/signing key. The external authority
pin and genesis scope must come from trusted provisioning. Compute the execution
profile before authority genesis; do not hash a scope-containing configuration
back into that profile.

`submit` creates one exclusive run and performs Reserve, Prepare, Finalize and
Deliver. Its immutable `run.json` records input hash/size before Reserve. The
`operation/` and `delivery/` journals retain separate copies of ciphertext, up to
approximately50MiB combined, plus bounded metadata. These are logical per-run
bounds, not a kernel disk quota or a global client storage limit.

For explicit steps use `create`, `reserve`, `prepare`, `finalize`,
`recover-authority`, `deliver`, `recover-delivery` and `status` with the same
configuration and run root. Only `submit`, `create` and `prepare` accept `--file`;
Prepare must match the original input intent. Opening history makes no network
request. An uncertain Finalize permits only a known-job authority GET; an
uncertain Deliver permits only a known-job upload GET. Neither recovery resends
ciphertext, creates another identity or starts execution. Unknown/partial history
stays fenced and retained. A failed command is not permission to delete its run
root or retry with a fresh one.

The upload ACK binds the signed acceptance's job, leaf credential, measured
ciphertext and decoded envelope. It is a claim by the upload service over TLS;
a compromised service can fabricate it. It is not an authority signature,
execution receipt or scientific release. See the
[owner delivery contract](../../docs/security/ownership-delivery-contract.md).

## Explicit legacy compatibility

```sh
go run . --protocol legacy --file /path/to/sample.fastq --client-id researcher-1
```

This retains the historical upload/results flow. It accepts `--mtls-cert`,
`--mtls-key`, `--ca-cert`, `--server-cert`, `--sign-key`, `--upload-url`,
`--results-url`, `--poll-seconds`, `--max-poll-errors` and `--wait-timeout`.
Owner failures never select this path automatically. Build or run the package
(`.`), since the executable now consists of multiple source files.
