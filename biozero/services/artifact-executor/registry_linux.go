//go:build linux

package artifactexecutor

import (
	"context"
	"io"
	"os"
	"sync"
	"syscall"
)

// InputRegistry is a trusted local registration API, never an RPC operation.
// Call Bind only after protected-entry signature/decryption verification. The
// original upload digest is taken from the durable reservation; ProcessedSHA256
// is independently supplied by that verifier and checked against the actual FD.
// Registry loss never permits replay: the Store's pending history blocks restart.
type InputRegistry struct {
	mu     sync.Mutex
	store  *Store
	inputs map[string]*scopedReference
	leases map[string]string
	closed bool
}

type scopedReference struct {
	lease, job, originalSHA, processedSHA string
	bytes                                 int64
	file                                  *os.File
	consumed                              bool
	analysis                              *AnalysisContext
}

// ScopedInput contains a private read-only descriptor, not a caller path. The
// opaque reference and lease must match before its one-time acquisition. Closing
// it does not release quota, clear history or establish provider quiescence.
type ScopedInput struct {
	mu              sync.Mutex
	JobID           string
	OriginalSHA256  string
	ProcessedSHA256 string
	Bytes           int64
	AnalysisContext *AnalysisContext
	file            *os.File
}

func NewInputRegistry(store *Store) (*InputRegistry, error) {
	if store == nil {
		return nil, fail("artifact_input_registry_invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return nil, err
	}
	return &InputRegistry{store: store, inputs: map[string]*scopedReference{}, leases: map[string]string{}}, nil
}

// duplicateReadOnly uses atomic CLOEXEC duplication; no lease/control descriptor
// is passed to a tool. A writable FD is rejected even if its path mode is 0600.
func duplicateReadOnly(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, fail("artifact_input_file_unsafe")
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, fail("artifact_input_file_unsafe")
	}
	var fd uintptr
	var dupErr syscall.Errno
	// Control holds the source FD alive across atomic duplication. A concurrent
	// File.Close cannot replace its descriptor number with an unrelated input.
	err = raw.Control(func(sourceFD uintptr) {
		fd, _, dupErr = syscall.Syscall(syscall.SYS_FCNTL, sourceFD, syscall.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || dupErr != 0 {
		return nil, fail("artifact_input_file_unsafe")
	}
	f := os.NewFile(fd, "artifact-scoped-input")
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY || !safeInfo(f, false) {
		f.Close()
		return nil, fail("artifact_input_file_unsafe")
	}
	return f, nil
}

func checkInputFile(f *os.File, expectedBytes int64) error {
	if !safeInfo(f, false) {
		return fail("artifact_input_file_unsafe")
	}
	info, err := f.Stat()
	if err != nil || info.Size() != expectedBytes {
		return fail("artifact_input_size_mismatch")
	}
	return nil
}

func (r *InputRegistry) Bind(ctx context.Context, lease string, source *os.File, processedSHA string, expectedBytes int64) (string, error) {
	return r.bind(ctx, lease, source, processedSHA, expectedBytes, nil)
}

// BindWithAnalysis binds a value copy of verifier-established facts to the
// same one-shot descriptor authority. The legacy Bind does not enable analysis.
func (r *InputRegistry) BindWithAnalysis(ctx context.Context, lease string, source *os.File, processedSHA string, expectedBytes int64, facts AnalysisContext) (string, error) {
	if err := validateAnalysisContext(facts, expectedBytes); err != nil {
		return "", err
	}
	return r.bind(ctx, lease, source, processedSHA, expectedBytes, &facts)
}

func (r *InputRegistry) bind(ctx context.Context, lease string, source *os.File, processedSHA string, expectedBytes int64, facts *AnalysisContext) (string, error) {
	if !hexID(lease, 32) || !hexID(processedSHA, 64) || expectedBytes < 0 || expectedBytes > MaxInputBytes || ctx.Err() != nil {
		return "", fail("artifact_input_binding_invalid")
	}
	r.store.mu.Lock()
	entry, exists := r.store.data.Records[lease]
	err := r.store.ready()
	maxRefs := r.store.data.Policy.Jobs
	r.store.mu.Unlock()
	if err != nil || !exists || entry.State != "reserved" {
		return "", fail("artifact_input_lease_unavailable")
	}
	f, err := duplicateReadOnly(source)
	if err != nil {
		return "", err
	}
	retained := false
	defer func() {
		if !retained {
			f.Close()
		}
	}()
	if err = checkInputFile(f, expectedBytes); err != nil {
		return "", err
	}
	// ReadAt ignores the caller's current offset. The second check and provider's
	// subsequent CopyTo catch changed bytes without claiming immutable host data.
	if _, err = ReceiveInput(ctx, io.Discard, io.NewSectionReader(f, 0, expectedBytes+1), expectedBytes, processedSHA); err != nil {
		return "", err
	}
	if err = checkInputFile(f, expectedBytes); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Publication lock ordering is registry -> store; no caller holds the store
	// lock while acquiring registry.mu. Revalidate after hashing, atomically with
	// granting the reference, so a concurrent Close/latch/Begin cannot win first.
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	current, exists := r.store.data.Records[lease]
	if ctx.Err() != nil || r.store.ready() != nil || !exists || current.State != "reserved" || current.JobID != entry.JobID || current.InputSHA256 != entry.InputSHA256 {
		return "", fail("artifact_input_lease_unavailable")
	}
	if r.closed || len(r.inputs) >= maxRefs || r.leases[lease] != "" {
		return "", fail("artifact_input_registry_unavailable")
	}
	var ref string
	for i := 0; i < 8; i++ {
		ref, err = token()
		if err != nil {
			return "", err
		}
		if _, exists := r.inputs[ref]; !exists {
			break
		}
		ref = ""
	}
	if ref == "" {
		return "", fail("artifact_random_failed")
	}
	r.inputs[ref] = &scopedReference{lease: lease, job: entry.JobID, originalSHA: entry.InputSHA256,
		processedSHA: processedSHA, bytes: expectedBytes, file: f, analysis: facts}
	r.leases[lease] = ref
	retained = true
	return ref, nil
}

// Acquire fences the reference before handing its FD to the trusted provider.
// Failure or cancellation never makes it reusable. The durable Store Begin must
// independently succeed before any tools or workspace are created.
func (r *InputRegistry) Acquire(lease, ref string) (*ScopedInput, error) {
	if !hexID(lease, 32) || !hexID(ref, 32) {
		return nil, fail("artifact_input_reference_unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.inputs[ref]
	if r.closed || entry == nil || entry.lease != lease || entry.consumed || entry.file == nil {
		return nil, fail("artifact_input_reference_unavailable")
	}
	input := &ScopedInput{JobID: entry.job, OriginalSHA256: entry.originalSHA,
		ProcessedSHA256: entry.processedSHA, Bytes: entry.bytes, file: entry.file}
	if entry.analysis != nil {
		facts := *entry.analysis
		input.AnalysisContext = &facts
	}
	entry.consumed = true
	entry.file = nil
	return input, nil
}

// CopyTo verifies exactly the separately bound plaintext bytes. It must write
// into the provider's already bounded workspace, never a caller-selected path.
// Failure may leave a partial private destination; no execution/release follows.
func (s *ScopedInput) CopyTo(ctx context.Context, dst io.Writer) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return 0, fail("artifact_input_reference_unavailable")
	}
	if err := checkInputFile(s.file, s.Bytes); err != nil {
		return 0, err
	}
	n, err := ReceiveInput(ctx, dst, io.NewSectionReader(s.file, 0, s.Bytes+1), s.Bytes, s.ProcessedSHA256)
	if err != nil {
		return n, err
	}
	if err = checkInputFile(s.file, s.Bytes); err != nil {
		return n, err
	}
	return n, nil
}

func (s *ScopedInput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (r *InputRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var first error
	for _, entry := range r.inputs {
		if entry.file != nil {
			if err := entry.file.Close(); first == nil && err != nil {
				first = err
			}
			entry.file = nil
		}
	}
	return first
}
