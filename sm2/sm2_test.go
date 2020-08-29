package sm2

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestSM2GenerateKey(t *testing.T) {
	c := SM2P256()
	for i := 0; i < 1000; i++ {
		sk, err := SM2GenerateKey(c, rand.Reader)
		assert.NoError(t, err)
		bl := c.IsOnCurve(sk.X, sk.Y)
		//assert.Equal(t, true, bl)
		assert.True(t, bl)
	}
}
func TestSetSM2PrivateKey(t *testing.T) {
	d, bl := new(big.Int).SetString("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8", 16)
	assert.True(t, bl)
	sk, err := SetSM2PrivateKey(SM2P256(), d)
	assert.NoError(t, err)
	bl = sk.IsOnCurve(sk.X, sk.Y)
	assert.True(t, bl)
	x, bl := new(big.Int).SetString("9F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020", 16)
	//9f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020
	assert.True(t, bl)
	y, bl := new(big.Int).SetString("CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13", 16)
	assert.True(t, bl)
	pk := SM2PublicKey{
		Curve: SM2P256(),
		X:     x,
		Y:     y,
	}
	assert.Equal(t, pk, sk.SM2PublicKey)
	t.Logf("X:%v,Y:%v\n", sk.X.Text(16), sk.Y.Text(16))
}
func TestPublicKey(t *testing.T) {
	//ecdsa.GenerateKey(SM2P256(), rand.Reader)
	initSM2P256()
	sk, bl := new(big.Int).SetString("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8", 16)
	//sk := new(big.Int).SetInt64(2)
	x, y := sm2P256.ScalarBaseMult(sk.Bytes())
	//out, _ := json.Marshal(sm2P256)
	//t.Log(string(out))
	t.Logf("p=%x\n", sm2P256.P.Bytes())
	t.Logf("sk=%x,bl=\n", sk.Bytes())
	t.Logf("x=%x\n", x.Bytes())
	t.Logf("y=%x\n", y.Bytes())

	bl = sm2P256.IsOnCurve(sm2P256.Gx, sm2P256.Gy)
	t.Logf("bool:%v\n", bl)
	//x, y = sm2P256.Double(sm2P256.Gx, sm2P256.Gy)
	//t.Logf("x=%x\n", x.Bytes())
	//t.Logf("y=%x\n", y.Bytes())
	//x, y := sm2P256.Add(sm2P256.Gx, sm2P256.Gy, sm2P256.Gx, sm2P256.Gy)
	//t.Logf("x=%x\n", x.Bytes())
	//t.Logf("y=%x\n", y.Bytes())
	for i := 0; i < 100; i++ {
		buf := make([]byte, 32)
		io.ReadFull(rand.Reader, buf)
		t.Logf("===%x\n", buf)
		assert.Equal(t, 32, len(buf))
		time.Sleep(time.Millisecond * 50)
	}

}
func TestHash(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("hello"))
	h.Write([]byte("golang"))
	h.Sum(nil)
	h.Write([]byte("boy"))
	res := h.Sum(nil)
	t.Logf("res:%x,len:%v\n", string(res), len(res))
	//
	h = sha256.New()
	h.Write([]byte("hello"))
	h.Write([]byte("golang"))
	//h.Sum(nil)
	h.Write([]byte("boy"))
	res = h.Sum(nil)
	t.Logf("res:%x\n", string(res))
	//
	//
	h = sha256.New()
	//h.Write([]byte("hello"))
	//h.Write([]byte("golang"))
	//h.Sum(nil)
	h.Write([]byte("hellogolangboy"))
	res = h.Sum(nil)
	t.Logf("res:%x\n", string(res))
	///
	var src []byte
	assert.Equal(t, true, src == nil)
	assert.True(t, src == nil)
	tt := []byte("aaaaaaa")
	s := append(src, tt...)
	t.Logf("s:%v\n", string(s))

}
