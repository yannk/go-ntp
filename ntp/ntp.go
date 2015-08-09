package ntp

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"
)

const (
	ReservedMode = iota
	SymmetricActiveMode
	SymmetricPassiveMode
	ClientMode
	ServerMode
	BroadcastMode
	ControlMsgMode
	PrivateMode
)

const HeaderSize = 48

var ErrOverflow = errors.New("Overflow")

var NTPEpoch = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)

type exponent int8

// Convert an exponent format to its float representation.
// the "10" exponent value means 2**10 = 1024
// the "-3" exponent value means 2**-3 = 0.125
func (e exponent) Float() float64 {
	if e < 0 {
		return 1. / float64(uint(1)<<uint(-e))
	}
	return float64(uint(1) << uint(e))
}

// FloatToExponent returns
func FloatToExponent(v float64) (exponent, error) {
	return exponent(math.Log2(v)), nil
}

type Short struct {
	Seconds  uint16
	Fraction uint16
}

type Timestamp struct {
	Seconds  uint32
	Fraction uint32
}

/*
* SNTP - RFC 2030
      It is advisable to fill the non-significant low order bits of the
      timestamp with a random, unbiased bitstring, both to avoid
      systematic roundoff errors and as a means of loop detection and
      replay detection (see below). One way of doing this is to generate
      a random bitstring in a 64-bit word, then perform an arithmetic
      right shift a number of bits equal to the number of significant
      bits of the timestamp, then add the result to the original
      timestamp.
*/

// NewTimestampFromTime converts a time object to its NTP Timestamp representation..
// TODO: reread spec about era. Most likely I need a new function to take that into account
// this one can focus on era 0 or something.
func NewTimestampFromTime(t time.Time) (Timestamp, error) {
	ts := Timestamp{}

	ns := t.Sub(NTPEpoch).Nanoseconds()
	s := ns / 1e9
	if s > int64(0xffffffff) || s < -int64(0xffffffff) {
		return ts, fmt.Errorf("Timestamp overflow: %s", t) // TODO(yann): overflow value error?
	}
	f := ns % 1e9
	ts.Seconds = uint32(s)

	// the time package exposes a nanosecond precision, which can be represented with a
	// 30bit fraction. So, in accordance with the RFC the last 2 LSB are randomly selected
	source := rand.NewSource(time.Now().UnixNano())
	lsb := rand.New(source).Intn(4)
	ts.Fraction = uint32(f << 32 / 1e9)
	ts.Fraction = ts.Fraction>>2<<2 | uint32(lsb)
	return ts, nil
}

// TimeFromTimestamp returns the closest time.Time object that can represent ts.
// TODO: Take precision into account
func TimeFromTimestamp(ts Timestamp) time.Time {
	return NTPEpoch.Add(time.Duration(int64(ts.Seconds)*1e9 + int64(ts.Fraction)*1e9>>32))
}

// NewShortFromDuration return a Short.
// possible errors are overflow
func NewShortFromDuration(d time.Duration) (Short, error) {
	sh := Short{}
	s := d.Nanoseconds() / 1e9
	if s > int64(0xffff) || s < -int64(0xffff) {
		return sh, fmt.Errorf("Timestamp overflow: %s", d) // TODO(yann): overflow value error?
	}
	return Short{
		Seconds:  uint16(s),
		Fraction: uint16((d.Nanoseconds() % 1e9) << 16 / 1e9),
	}, nil
}

// Msg is a NTP Msg as defined in RFC5905
type Msg struct {
	Header          MsgHeader
	ExtensionFields []ExtensionField
	KeyID           uint32
	Dgst            [16]byte
}

// MsgHeader is the mandatory header variables. Its values are common between
// NTPv3 and NTPv4
type MsgHeader struct {
	Leap      uint8
	Version   uint8
	Mode      uint8
	Stratum   uint8
	Poll      exponent
	Precision exponent
	RootDelay Short
	RootDisp  Short

	// RefID is a 4 chars string for stratum 0
	// Otherwise a v4 IP address
	RefID   [4]byte
	RefTime Timestamp
	Org     Timestamp // T1
	Rec     Timestamp // T2
	Xmt     Timestamp // T3
	Dst     Timestamp // T4
}

type ClientMsg struct {
	*Msg
}

// TODO(yann) struct methods?
func packShort(st Short, b []byte) {
	b[0] = byte(st.Seconds >> 8)
	b[1] = byte(st.Seconds & 0xff)
	b[2] = byte(st.Fraction >> 8)
	b[3] = byte(st.Fraction & 0xff)
}

func unpackShort(b []byte) Short {
	return Short{
		Seconds:  uint16(b[0])<<8 | uint16(b[1]),
		Fraction: uint16(b[2])<<8 | uint16(b[3]),
	}
}

func packTimestamp(st Timestamp, b []byte) {
	b[0] = byte(st.Seconds >> 24)
	b[1] = byte(st.Seconds >> 16 & 0xff)
	b[2] = byte(st.Seconds >> 8 & 0xff)
	b[3] = byte(st.Seconds & 0xff)
	b[4] = byte(st.Fraction >> 24)
	b[5] = byte(st.Fraction >> 16 & 0xff)
	b[6] = byte(st.Fraction >> 8 & 0xff)
	b[7] = byte(st.Fraction & 0xff)
}

func unpackTimestamp(b []byte) Timestamp {
	return Timestamp{
		Seconds:  uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
		Fraction: uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
	}
}

// Unpack reads a NTP Msg from a byte slice into m.
// TODO(yann): should we return an error? What would be the error? Panic / catch Out of bounds?
func (mh *MsgHeader) Unpack(b []byte) (err error) {
	mh.Leap = b[0] >> 6
	mh.Version = (b[0] >> 3) & 0x7
	mh.Mode = b[0] & 0x7
	mh.Stratum = b[1]
	mh.Poll = exponent(b[2])
	mh.Precision = exponent(b[3])
	mh.RootDelay = unpackShort(b[4:8])
	mh.RootDisp = unpackShort(b[8:12])
	mh.RefID = [4]byte{b[12], b[13], b[14], b[15]}
	mh.Org = unpackTimestamp(b[16:24])
	mh.Rec = unpackTimestamp(b[24:32])
	mh.Xmt = unpackTimestamp(b[32:40])
	mh.Dst = unpackTimestamp(b[40:48])
	return nil
}

func (mh *MsgHeader) Pack(buf []byte) (msg []byte, err error) {
	buf[0] = mh.Leap<<6 | mh.Version<<3 | mh.Mode
	buf[1] = mh.Stratum
	buf[2] = byte(mh.Poll)
	buf[3] = byte(mh.Precision)
	packShort(mh.RootDelay, buf[4:8])
	packShort(mh.RootDisp, buf[8:12])
	return nil, nil
}

// Pack writes a NTP Msg to a buf byte slice.
// if buf is too small a new slice is allocated. (TODO, is it what we want?)
func (m *Msg) Pack(buf []byte) (msg []byte, err error) {
	m.Header.Pack(buf)
	if m.Header.Version < 4 {
		return buf, nil
	}
	m.packExtensionFields(buf[len(buf):cap(buf)])
	i := 0 // FIXME

	buf[i] = byte(m.KeyID >> 24)
	buf[i+1] = byte(m.KeyID >> 16 & 0xff0000)
	buf[i+2] = byte(m.KeyID >> 8 & 0xff00)
	buf[i+3] = byte(m.KeyID & 0xff)
	i = i + 3

	for j := 0; j < 16; i++ {
		buf[i+j] = m.Dgst[i]
	}

	return buf, nil
}

func (m *Msg) Unpack(b []byte) error {
	err := m.Header.Unpack(b)
	if err != nil {
		return err
	}
	if m.Header.Version < 4 {
		return nil
	}
	end := len(b) + 1
	remain := end - HeaderSize
	if remain > 1 {
		if remain < 4+len(m.Dgst)+5 { // keyid + dgst + min(extfield)
			return fmt.Errorf("not enough data following header: %d bytes", remain)
		}
		/*
			Key Identifier (keyid): 32-bit unsigned integer used by the client
			and server to designate a secret 128-bit MD5 key.

			Message Digest (digest): 128-bit MD5 hash computed over the key
			followed by the NTP packet header and extensions fields (but not the
			Key Identifier or Message Digest fields).
		*/
		// We start by the end of the byte buffer to get the fixed
		// size fields.
		for i := 15; i >= 0; i-- {
			m.Dgst[i] = b[end-i-1]
		}

		end = end - len(m.Dgst) // end of KeyID: before Dgst
		m.KeyID = uint32(b[end-4])<<24 | uint32(b[end-3])<<16 | uint32(b[end-2])<<8 | uint32(b[end-1])

		end = end - 4 // e is now the end of extension fields
		m.unpackExtensionFields(b[HeaderSize:end])
	}

	return nil
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Field Type           |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   .                            Value                              .
   .                                                               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Padding (as needed)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// ExtensionFields is the NTPv4 extensions as defined in RFC5905 Section 7.5
type ExtensionField struct {
	Type  byte
	Value []byte
}

// Len returns the length of the ExtensionField Value.
func (e *ExtensionField) Len() uint8 {
	return uint8(len(e.Value))
}

func (m *Msg) unpackExtensionFields(b []byte) error {
	//FIXME(yann): This dies horribly if a packet is malformed
	i := 0
	for i < len(b) {
		// TODO(yann): verify and test this
		t, l := b[i], int(b[i+1])
		startVal := i + 2
		endVal := l + startVal
		val := b[startVal:endVal]

		// Advance i of needed padding
		padding := 4 - (l % 4)
		if padding != 0 {
			i += padding
		}
		e := ExtensionField{
			Type:  t,
			Value: val,
		}
		m.ExtensionFields = append(m.ExtensionFields, e)
	}
	return nil
}

func (m *Msg) packExtensionFields(buf []byte) (msg []byte, err error) {
	i := 0
	for _, extensionField := range m.ExtensionFields {
		l := extensionField.Len()
		padding := int(4 - (l % 4))
		buf[i] = extensionField.Type
		buf[i+1] = l
		startVal := i + 2
		endVal := startVal + int(l)
		copy(buf[startVal:endVal], extensionField.Value)
		i = endVal + padding
	}
	return buf, nil
}

//func NewClientMsg() ClientMsg
