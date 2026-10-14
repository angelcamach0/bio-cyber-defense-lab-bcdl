package artifactexecutor

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
)

func strictJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := scanJSON(d, 0)
	if err != nil {
		return fail("artifact_json_invalid")
	}
	if _, err = d.Token(); err != io.EOF {
		return fail("artifact_json_invalid")
	}
	if !typedJSON(v, reflect.TypeOf(dst).Elem()) {
		return fail("artifact_json_invalid")
	}
	if json.Unmarshal(data, dst) != nil {
		return fail("artifact_json_invalid")
	}
	return nil
}
func scanJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fail("artifact_json_invalid")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok {
				return nil, fail("artifact_json_invalid")
			}
			if _, ok = m[key]; ok {
				return nil, fail("artifact_json_invalid")
			}
			v, e := scanJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = v
		}
		_, e = d.Token()
		return m, e
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, e := scanJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	default:
		return t, nil
	}
}
func typedJSON(v any, t reflect.Type) bool {
	if v == nil {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[f.Tag.Get("json")] = f.Type
		}
		if len(fields) != len(m) {
			return false
		}
		for k, x := range m {
			ft, ok := fields[k]
			if !ok || !typedJSON(x, ft) {
				return false
			}
		}
		return true
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, x := range m {
			if !typedJSON(x, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !typedJSON(x, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Bool:
		_, ok := v.(bool)
		return ok
	case reflect.Int, reflect.Int64, reflect.Uint32:
		_, ok := v.(json.Number)
		return ok
	default:
		return false
	}
}
