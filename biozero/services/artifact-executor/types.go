package artifactexecutor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
)

const ledgerLimit int64 = 1 << 20
const proofLimit int64 = 16 << 10
const manifestLimit int64 = 32 << 10
const storeHeaderReserve int64 = 4096

type Policy struct {
	GlobalBytes         int64    `json:"global_bytes"`
	Jobs                int      `json:"jobs"`
	ExportBytes         int64    `json:"export_bytes"`
	PublicationHeadroom int64    `json:"publication_headroom"`
	ArtifactIDs         []string `json:"artifact_ids"`
}

func DefaultPolicy() Policy {
	return Policy{1 << 30, 64, 64 << 20, 128 << 10, []string{"normalized_vcf", "variants_vcf", "variants_vcf_index"}}
}
func (p Policy) validate() error {
	if p.GlobalBytes <= storeHeaderReserve || p.GlobalBytes > 1<<30 || p.Jobs < 1 || p.Jobs > 64 || p.ExportBytes < 1 || p.ExportBytes > 64<<20 || p.PublicationHeadroom != 128<<10 || len(p.ArtifactIDs) == 0 || len(p.ArtifactIDs) > 16 {
		return fail("artifact_policy_invalid")
	}
	seen := map[string]bool{}
	for _, id := range p.ArtifactIDs {
		if !artifactName.MatchString(id) || seen[id] {
			return fail("artifact_policy_invalid")
		}
		seen[id] = true
	}
	if !seen["normalized_vcf"] {
		return fail("artifact_policy_invalid")
	}
	if !sort.StringsAreSorted(p.ArtifactIDs) {
		return fail("artifact_policy_invalid")
	}
	return nil
}

var artifactCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var artifactName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func hexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func fail(code string) error { return errors.New(code) }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func token() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", fail("artifact_random_failed")
	}
	return hex.EncodeToString(b), nil
}
func jsonBytes(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, fail("artifact_json_invalid")
	}
	return b, nil
}

type FileRecord struct {
	State  string `json:"state"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Record struct {
	JobID          string                `json:"job_id"`
	InputSHA256    string                `json:"input_sha256"`
	State          string                `json:"state"`
	Charge         int64                 `json:"charge"`
	Files          map[string]FileRecord `json:"files"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	ProofSHA256    string                `json:"proof_sha256"`
}
type ledger struct {
	SchemaVersion int               `json:"schema_version"`
	StoreID       string            `json:"store_id"`
	Policy        Policy            `json:"policy"`
	Records       map[string]Record `json:"records"`
}
type Outcome struct {
	ExecutionStatus string
	ReleaseStatus   string
	ErrorCode       string
	ObservedSHA256  string
	EvaluatedSHA256 string
}

type Manifest struct {
	SchemaVersion   int                   `json:"schema_version"`
	StoreID         string                `json:"store_id"`
	PolicySHA256    string                `json:"policy_sha256"`
	LeaseID         string                `json:"lease_id"`
	JobID           string                `json:"job_id"`
	InputSHA256     string                `json:"input_sha256"`
	ObservedSHA256  string                `json:"observed_sha256"`
	EvaluatedSHA256 string                `json:"evaluated_sha256"`
	Files           map[string]FileRecord `json:"files"`
	ExecutionStatus string                `json:"execution_status"`
	ReleaseStatus   string                `json:"release_status"`
	ErrorCode       string                `json:"error_code"`
}

// Proof is accepted only via the trusted keeper API, never from worker RPC.
// Namespace identity/PID fields alone are deliberately insufficient authority.
type Proof struct {
	SchemaVersion         int    `json:"schema_version"`
	StoreID               string `json:"store_id"`
	PolicySHA256          string `json:"policy_sha256"`
	LeaseID               string `json:"lease_id"`
	JobID                 string `json:"job_id"`
	InputSHA256           string `json:"input_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
	CapsuleWaitFinished   bool   `json:"capsule_wait_finished"`
	ExportAuthorityClosed bool   `json:"export_authority_closed"`
}
type Snapshot struct {
	RetainedOrReservedJobs int
	ChargedBytes           int64
	Healthy                bool
}
