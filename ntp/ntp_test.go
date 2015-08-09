package ntp

import (
	"testing"
	"time"
)

const tolerance = 10

func TestExponent(t *testing.T) {
	var exp exponent
	if exp != 0 {
		t.Errorf("Zero value is incorrect: %d", exp)
	}

	for _, test := range []struct {
		exponent exponent
		expected float64
	}{
		{exponent(0), 1.0},
		{exponent(10), 1024.},
		{exponent(3), 8.0},
		{exponent(-3), 0.125},
	} {
		if v := test.exponent.Float(); v != test.expected {
			t.Errorf("exponent value doesn't decode in seconds correctly: %f, expected=%f", v, test.expected)
		}
	}

	for _, test := range []float64{1.0, 1 << 10, 1 << 20, 1. / 1 << 3, 1. / 1 << 20} {
		e, _ := FloatToExponent(test)
		if f := e.Float(); f != test {
			t.Errorf("encode/decode of a float to exponent and back doesn't value: %f, back=%f", test, f)
		}
	}

	// Limits
	for _, test := range []float64{} {
		if _, err := FloatToExponent(test); err != nil {
			t.Errorf("Expected error for %f", test)
		}
	}
}

func TestTimestamp(t *testing.T) {
	s := Timestamp{}
	if s.Seconds != 0 {
		t.Errorf("seconds zero value is wrong: %v", s.Seconds)
	}
	if s.Fraction != 0 {
		t.Errorf("fraction zero value is wrong: %v", s.Fraction)
	}
	for _, test := range []struct {
		time time.Time
		ts   Timestamp
		err  error
	}{
		{NTPEpoch, Timestamp{0, 0}, nil},
		{time.Date(1974, 04, 1, 15, 0, 0, 0, time.UTC), Timestamp{2343049200, 0}, nil},
		{time.Date(1974, 04, 1, 15, 0, 0, 1, time.UTC), Timestamp{2343049200, 4}, nil},
		{time.Date(2014, 10, 13, 14, 0, 0, 0, time.UTC), Timestamp{3622197600, 0}, nil},
	} {
		s, err := NewTimestampFromTime(test.time)
		if err != test.err {
			t.Errorf("got error mismatch: %s: %s, %s", test.time, err, test.err)
		}
		if !matchTimestampWithPrecision(s, test.ts, 30) {
			t.Errorf("%v and %v don't match", s, test.ts)
		}
		if tt := TimeFromTimestamp(s); !matchTimeApprox(tt, test.time) {
			t.Errorf("conversion from timestamp to Time didn't work: %s %s", tt, test.time)
		}
	}
}

func TestTimestampPacking(t *testing.T) {
	for _, ti := range []time.Time{
		time.Now(),
		NTPEpoch,
		time.Date(1974, 04, 1, 15, 0, 0, 0, time.UTC),
		time.Date(1974, 04, 1, 15, 0, 0, 1, time.UTC),
		time.Date(2014, 10, 13, 14, 0, 0, 0, time.UTC),
		time.Date(2136, 02, 20, 14, 0, 0, 0, time.UTC),
	} {
		ts, _ := NewTimestampFromTime(ti)
		b := make([]byte, 8)
		packTimestamp(ts, b)
		if ts2 := unpackTimestamp(b); !matchTimestampExact(ts2, ts) {
			t.Errorf("unpack/pack error: %s, %s", ts2, ts)
		}
	}
}

func TestShortPacking(t *testing.T) {
	for _, ti := range []time.Duration{
		time.Duration(40 * time.Hour * 24),
		time.Duration(4 * time.Hour * 24),
		time.Duration(4 * time.Hour),
		time.Duration(4 * time.Minute),
		time.Duration(4 * time.Second),
		time.Duration(4 * time.Millisecond),
		time.Duration(4 * time.Microsecond),
		time.Duration(4 * time.Nanosecond),
	} {
		ts, _ := NewShortFromDuration(ti)
		b := make([]byte, 8)
		packShort(ts, b)
		if ts2 := unpackShort(b); !matchShortExact(ts2, ts) {
			t.Errorf("unpack/pack error: %s, %s", ts2, ts)
		}
	}

	// test overflow
	for _, v := range []int64{0x10000, -0x10000} {
		dur := time.Duration(v * 1e9)
		_, err := NewShortFromDuration(dur)
		if err == nil {
			t.Errorf("Expected an error, but got success: %s", dur)
		}
	}
}

// make sure two times are within tolerance
func matchTimeApprox(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		if d > -tolerance {
			return true
		}
		return false
	}
	if d > tolerance {
		return false
	}
	return true
}

func matchShortWithPrecision(a, b Short, precision uint) bool {
	if a.Seconds != b.Seconds {
		return false
	}
	mask := uint16(0xffff >> (16 - precision) << (16 - precision))
	aFrac := a.Fraction & mask
	bFrac := b.Fraction & mask
	if aFrac != bFrac {
		return false
	}
	return true
}

func matchTimestampWithPrecision(a, b Timestamp, precision uint) bool {
	if a.Seconds != b.Seconds {
		return false
	}
	mask := uint32(0xffffffff >> (32 - precision) << (32 - precision))
	aFrac := a.Fraction & mask
	bFrac := b.Fraction & mask
	if aFrac != bFrac {
		return false
	}
	return true
}

func matchTimestampExact(a, b Timestamp) bool {
	return matchTimestampWithPrecision(a, b, 32)
}

func matchShortExact(a, b Short) bool {
	return matchShortWithPrecision(a, b, 16)
}
