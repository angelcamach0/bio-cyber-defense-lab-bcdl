//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// The ledger has a closed schema, including every field of every record. Its
// only collection is a bounded list of at most 64 records; no arbitrary maps.
func decodeStoreJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > StoreLedgerLimit || !utf8.Valid(raw) {
		return fail("ownership_ledger_invalid")
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return fail("ownership_ledger_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanStoreJSON(d, t.Elem(), 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fail("ownership_ledger_invalid")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return fail("ownership_ledger_invalid")
	}
	return nil
}

func scanStoreJSON(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 64 {
		return fail("ownership_ledger_invalid")
	}
	v, err := d.Token()
	if err != nil || v == nil {
		return fail("ownership_ledger_invalid")
	}
	switch t.Kind() {
	case reflect.Struct:
		if v != json.Delim('{') {
			return fail("ownership_ledger_invalid")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			name, ok := key.(string)
			ft, known := fields[name]
			if e != nil || !ok || !known || seen[name] {
				return fail("ownership_ledger_invalid")
			}
			seen[name] = true
			if e = scanStoreJSON(d, ft, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return fail("ownership_ledger_invalid")
		}
		return nil
	case reflect.Slice:
		if v != json.Delim('[') {
			return fail("ownership_ledger_invalid")
		}
		count := 0
		for d.More() {
			count++
			if count > 64 {
				return fail("ownership_ledger_invalid")
			}
			if err := scanStoreJSON(d, t.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return fail("ownership_ledger_invalid")
		}
		return nil
	case reflect.String:
		if _, ok := v.(string); ok {
			return nil
		}
	case reflect.Int, reflect.Int64:
		if _, ok := v.(json.Number); ok {
			return nil
		}
	}
	return fail("ownership_ledger_invalid")
}
