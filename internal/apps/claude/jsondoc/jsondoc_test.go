package jsondoc

import (
	"bytes"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// jq runs the real jq, where there is one, as the oracle the scripts this
// package replaces were written against.
// Laid out as jq lays it out, key order and all.
// The numbers whose literal jq rewrites and this keeps: the one known
// difference from jq's layout, said in the package comment. If jq starts or
// stops rewriting one of them, this says so.
func TestParseRefusesWhatJqRefuses(t *testing.T) {
	for _, d := range []string{``, ` `, `1 2`, `{} {}`, `{`, `{"a":}`, `{"a":1}x`, `{a:1}`, `[1,]`} {
		if _, err := Parse([]byte(d)); err == nil {
			t.Errorf("parsed %q", d)
		}
	}
}

func TestFieldAndSetFieldFollowJq(t *testing.T) {
	obj := Obj(Member{"a", Str("x")})
	cases := []struct {
		v    Value
		ok   bool
		want Value
	}{
		{obj, true, Str("x")},
		{Obj(), true, Value{Kind: Null}},
		{Value{Kind: Null}, true, Value{Kind: Null}},
		{Str("s"), false, Value{}},
		{Value{Kind: Array}, false, Value{}},
		{Value{Kind: Number, Num: "1"}, false, Value{}},
		{True, false, Value{}},
	}
	for _, c := range cases {
		got, err := c.v.Field("a")
		if (err == nil) != c.ok || (c.ok && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%v.a = %v, %v", c.v.Kind, got, err)
		}
		_, err = c.v.SetField("a", True)
		if (err == nil) != c.ok {
			t.Errorf("%v.a = true: %v", c.v.Kind, err)
		}
	}

	// Replaced where it stands, added last, and the original left alone.
	two := Obj(Member{"a", Str("1")}, Member{"b", Str("2")})
	got, _ := two.SetField("a", True)
	if string(got.Marshal()) != "{\n  \"a\": true,\n  \"b\": \"2\"\n}" {
		t.Errorf("replaced: %s", got.Marshal())
	}
	got, _ = two.SetField("c", True)
	if string(got.Marshal()) != "{\n  \"a\": \"1\",\n  \"b\": \"2\",\n  \"c\": true\n}" {
		t.Errorf("added: %s", got.Marshal())
	}
	if len(two.Obj) != 2 || two.Obj[0].Value.Str != "1" {
		t.Errorf("the original changed: %v", two)
	}
	got, _ = Value{Kind: Null}.SetField("a", True)
	if string(got.Marshal()) != "{\n  \"a\": true\n}" {
		t.Errorf("of null: %s", got.Marshal())
	}
}

func TestOrIsJqsAlternative(t *testing.T) {
	alt := Str("alt")
	for _, c := range []struct {
		v    Value
		want Value
	}{
		{Value{Kind: Null}, alt},
		{Value{Kind: Bool}, alt},
		{True, True},
		{Str(""), Str("")},
		{Value{Kind: Number, Num: "0"}, Value{Kind: Number, Num: "0"}},
	} {
		if got := c.v.Or(alt); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v // alt = %v", c.v, got)
		}
	}
}

func strs(ss []string) []Value {
	out := []Value{}
	for _, s := range ss {
		out = append(out, Str(s))
	}
	return out
}

// marshalCompact is jq -c, for comparing to it in tests.
func (v Value) marshalCompact() (string, error) {
	var b bytes.Buffer
	switch v.Kind {
	case Array:
		b.WriteString("[")
		for i, e := range v.Arr {
			if i > 0 {
				b.WriteString(",")
			}
			s, _ := e.marshalCompact()
			b.WriteString(s)
		}
		b.WriteString("]")
	default:
		b.Write(v.Marshal())
	}
	return b.String(), nil
}

// What it prints it reads back as the same value, and prints the same way.
func TestMarshalRoundTrips(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		v := genValue(3).Draw(rt, "v")
		out := v.Marshal()
		back, err := Parse(out)
		if err != nil {
			rt.Fatalf("%s: %v", out, err)
		}
		if again := back.Marshal(); !bytes.Equal(out, again) {
			rt.Fatalf("%s\nbecame\n%s", out, again)
		}
	})
}

func genValue(depth int) *rapid.Generator[Value] {
	return rapid.Custom(func(rt *rapid.T) Value {
		max := 5
		if depth == 0 {
			max = 3
		}
		switch rapid.IntRange(0, max).Draw(rt, "kind") {
		case 0:
			return Value{Kind: Null}
		case 1:
			return Value{Kind: Bool, Bool: rapid.Bool().Draw(rt, "b")}
		case 2:
			return Value{Kind: Number, Num: rapid.StringMatching(`-?(0|[1-9][0-9]{0,15})(\.[0-9]{1,4})?`).Draw(rt, "n")}
		case 3:
			return Str(rapid.String().Draw(rt, "s"))
		case 4:
			return Value{Kind: Array, Arr: rapid.SliceOfN(genValue(depth-1), 0, 3).Draw(rt, "a")}
		default:
			keys := rapid.SliceOfNDistinct(rapid.String(), 0, 3, rapid.ID[string]).Draw(rt, "k")
			o := Obj()
			for _, k := range keys {
				o = o.set(k, genValue(depth-1).Draw(rt, "v"))
			}
			return o
		}
	})
}
