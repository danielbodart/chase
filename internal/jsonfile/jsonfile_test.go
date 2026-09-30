package jsonfile

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A document decoded and encoded again is the same document: every member
// kept, and each number the literal it was written as.
func TestRoundTripKeepsEverything(t *testing.T) {
	in := `{"z":1,"a":{"n":12345678901234567890123,"f":0.1000000000000000055511151231257827,` +
		`"e":1e400,"d":1.50,"neg":-0},"l":[null,true,false,"s",[],{}],"u":"é\u0001"}`
	v, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(out)
	if err != nil || !reflect.DeepEqual(v, again) {
		t.Errorf("became\n%s", out)
	}
	for k, want := range map[string]json.Number{"n": "12345678901234567890123", "f": "0.1000000000000000055511151231257827", "e": "1e400", "d": "1.50", "neg": "-0"} {
		if got := v.(map[string]any)["a"].(map[string]any)[k]; got != want {
			t.Errorf("%s is %#v", k, got)
		}
	}
}

func TestEncodeLayout(t *testing.T) {
	out, err := Encode(map[string]any{"b": "<&>", "a": []any{json.Number("1")}})
	want := "{\n  \"a\": [\n    1\n  ],\n  \"b\": \"<&>\"\n}\n"
	if err != nil || string(out) != want {
		t.Errorf("%q, %v", out, err)
	}
}

// One value, and nothing after it: an edit that read only the first would
// write back a file without the rest.
func TestDecodeRefusesAllButOneValue(t *testing.T) {
	for _, in := range []string{``, ` `, `{`, `{} {}`, `{}}`, `1 2`, `nul`, `{"a":1,}`} {
		if v, err := Decode([]byte(in)); err == nil {
			t.Errorf("%q: read %#v", in, v)
		}
	}
	for _, in := range []string{` {} `, "null\n", `"s"`} {
		if _, err := Decode([]byte(in)); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestObject(t *testing.T) {
	if m, ok := Object(nil); !ok || m == nil || len(m) != 0 {
		t.Errorf("null: %v, %v", m, ok)
	}
	in := map[string]any{"k": 1}
	if m, ok := Object(in); !ok || !reflect.DeepEqual(m, in) {
		t.Errorf("object: %v, %v", m, ok)
	}
	for _, v := range []any{[]any{}, "s", json.Number("1"), true, false} {
		if _, ok := Object(v); ok {
			t.Errorf("%#v is an object", v)
		}
	}
}

func TestOr(t *testing.T) {
	for _, c := range []struct{ v, want any }{
		{nil, "d"}, {false, "d"}, {true, true}, {"", ""}, {json.Number("0"), json.Number("0")},
	} {
		if got := Or(c.v, "d"); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%#v: %#v", c.v, got)
		}
	}
}
