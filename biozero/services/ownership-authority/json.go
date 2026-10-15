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

// All wire structs have required exact-case fields. Token validation precedes
// typed decoding: encoding/json alone accepts duplicate/case-aliased/null keys.
func strictJSON(raw []byte, target any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return fail("ownership_json_size_invalid")
	}
	if !utf8.Valid(raw) {
		return fail("ownership_json_invalid")
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer {
		return fail("ownership_json_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanValue(d, t.Elem(), 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fail("ownership_json_trailing")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return fail("ownership_json_type_invalid")
	}
	return nil
}

func scanValue(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 64 {
		return fail("ownership_json_depth_invalid")
	}
	v, err := d.Token()
	if err != nil || v == nil {
		return fail("ownership_json_invalid")
	}
	if t.Kind() == reflect.Struct {
		if v != json.Delim('{') {
			return fail("ownership_json_type_invalid")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			ft, known := fields[name]
			if err != nil || !ok || !known || seen[name] {
				return fail("ownership_json_key_invalid")
			}
			seen[name] = true
			if err := scanValue(d, ft, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return fail("ownership_json_fields_invalid")
		}
		return nil
	}
	switch t.Kind() {
	case reflect.String:
		if _, ok := v.(string); ok {
			return nil
		}
	case reflect.Int, reflect.Int64:
		if _, ok := v.(json.Number); ok {
			return nil
		}
	}
	return fail("ownership_json_type_invalid")
}

func boundedJSON(v any, limit int) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > limit {
		return nil, fail("ownership_json_size_invalid")
	}
	return raw, nil
}
