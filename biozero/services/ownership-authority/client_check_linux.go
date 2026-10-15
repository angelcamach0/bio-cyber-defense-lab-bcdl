//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

// Check validates retained custody without network IO or advancing a phase.
// It never waits behind a mutating method's upstream request. Busy is a distinct
// temporary condition; callers must not interpret it as healthy checked custody.
func (o *ClientOperation) Check() error {
	if o == nil {
		return fail("ownership_client_unavailable")
	}
	if !o.mu.TryLock() {
		return fail("ownership_client_busy")
	}
	defer o.mu.Unlock()
	return o.preflight()
}

// Check has the same nonblocking, query-only contract for transport custody.
func (d *ClientDelivery) Check() error {
	if d == nil {
		return fail("ownership_delivery_unavailable")
	}
	if !d.mu.TryLock() {
		return fail("ownership_delivery_busy")
	}
	defer d.mu.Unlock()
	return d.preflight()
}
