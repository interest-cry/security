package sm2

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

//type SM2PulicKey ecdsa.PublicKey
type SM2PublicKey struct {
	Curve
	X, Y *big.Int
}

// PrivateKey represents an sm2 private key.
type SM2PrivateKey struct {
	SM2PublicKey
	D *big.Int
}

var ErrorPrivateField = errors.New("private is not in field, error")

// GenerateKey generates a public and private key pair.
func SM2GenerateKey(c Curve, rand io.Reader) (*SM2PrivateKey, error) {
	k, err := RandGenerateFieldNumber(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(SM2PrivateKey)
	priv.SM2PublicKey.Curve = c
	priv.D = k
	priv.SM2PublicKey.X, priv.SM2PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}
func SetSM2PrivateKey(c Curve, d *big.Int) (*SM2PrivateKey, error) {
	if d.Cmp(one) <= 0 || d.Cmp(c.Params().N) >= 0 {
		return nil, ErrorPrivateField
	}
	x, y := c.ScalarBaseMult(d.Bytes())
	pk := SM2PublicKey{
		Curve: c,
		X:     x,
		Y:     y,
	}
	return &SM2PrivateKey{
		SM2PublicKey: pk,
		D:            d,
	}, nil
}

var one = new(big.Int).SetInt64(1)

// randGenerateFieldElement returns a random element of the field underlying the given
func RandGenerateFieldNumber(c Curve, rand io.Reader) (k *big.Int, err error) {
	return randGenerateFieldElement(c, rand)
}
func randGenerateFieldElement(c Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

type Curve interface {
	// Params returns the parameters for the curve.
	Params() *SM2CurveParam
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *big.Int) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// Double returns 2*(x,y)
	Double(x1, y1 *big.Int) (x, y *big.Int)
	// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
	ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int)
	// ScalarBaseMult returns k*G, where G is the base point of the group
	// and k is an integer in big-endian form.
	ScalarBaseMult(k []byte) (x, y *big.Int)
}
type SM2CurveParam struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
	//*elliptic.CurveParams
	A *big.Int
}

func (curve *SM2CurveParam) Params() *SM2CurveParam {
	return curve
}
func (curve *SM2CurveParam) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ +ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	//
	aX := new(big.Int).Mul(curve.A, x)
	aX.Mod(aX, curve.P)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	return x3.Cmp(y2) == 0
}

func (curve *SM2CurveParam) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	fmt.Printf("z1:%x,z2:%x\n", z1.Bytes(), z2.Bytes())
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}
func (curve *SM2CurveParam) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	//fmt.Printf("x1=%x\n", x1.Bytes())
	//fmt.Printf("y1=%x\n", y1.Bytes())
	//fmt.Printf("x2=%x\n", x2.Bytes())
	//fmt.Printf("y2=%x\n", y2.Bytes())

	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}
	//fmt.Println("dshaghashdh=========")
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	lamta2 := new(big.Int).Mul(x2, z1z1)
	lamta2.Mod(lamta2, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)
	lamta1 := new(big.Int).Mul(x1, z2z2)
	lamta1.Mod(lamta1, curve.P)
	lamta3 := new(big.Int).Sub(lamta1, lamta2)
	if lamta3.Sign() == -1 {
		lamta3.Add(lamta3, curve.P)
	}
	lamta3Square := new(big.Int).Mul(lamta3, lamta3)
	lamta3Square.Mod(lamta3Square, curve.P)
	z2z2z2 := new(big.Int).Mul(z2z2, z2)
	z2z2z2.Mod(z2z2z2, curve.P)
	lamta4 := new(big.Int).Mul(y1, z2z2z2)
	lamta4.Mod(lamta4, curve.P)

	z1z1z1 := new(big.Int).Mul(z1z1, z1)
	z1z1z1.Mod(z1z1z1, curve.P)
	lamta5 := new(big.Int).Mul(y2, z1z1z1)
	lamta5.Mod(lamta5, curve.P)
	lamta6 := new(big.Int).Sub(lamta4, lamta5)
	if lamta6.Sign() == -1 {
		lamta6.Add(lamta6, curve.P)
	}
	lamta6Square := new(big.Int).Mul(lamta6, lamta6)
	lamta6Square.Mod(lamta6Square, curve.P)
	lamta7 := new(big.Int).Add(lamta1, lamta2)
	lamta7.Mod(lamta7, curve.P)

	lamta8 := new(big.Int).Add(lamta4, lamta5)
	lamta8.Mod(lamta8, curve.P)
	lmt7Lmt3Square := new(big.Int).Mul(lamta7, lamta3Square)
	lmt7Lmt3Square.Mod(lmt7Lmt3Square, curve.P)
	x3 = new(big.Int).Sub(lamta6Square, lmt7Lmt3Square)
	if x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	lamta9 := new(big.Int).Sub(lmt7Lmt3Square, new(big.Int).Lsh(x3, 1))
	if lamta9.Sign() == -1 {
		lamta9.Add(lamta9, curve.P)
	}

	lmt3lm3lmt3 := new(big.Int).Mul(lamta3Square, lamta3)
	lmt3lm3lmt3.Mod(lmt3lm3lmt3, curve.P)
	tmpInt1 := new(big.Int).Mul(lamta8, lmt3lm3lmt3)
	tmpInt1.Mod(tmpInt1, curve.P)
	tmpInt2 := new(big.Int).Mul(lamta9, lamta6)
	tmpInt2.Mod(tmpInt2, curve.P)
	tmpInt3 := new(big.Int).Sub(tmpInt2, tmpInt1)
	if tmpInt3.Sign() == -1 {
		tmpInt3.Add(tmpInt3, curve.P)
	}
	inv2 := new(big.Int).ModInverse(new(big.Int).SetInt64(2), curve.P)
	y3 = new(big.Int).Mul(tmpInt3, inv2)
	y3.Mod(y3, curve.P)
	//z3
	tmpInt1.Mul(z1, z2)
	tmpInt1.Mod(tmpInt1, curve.P)
	z3 = new(big.Int).Mul(tmpInt1, lamta3)
	z3.Mod(z3, curve.P)
	//fmt.Printf("x3=%x\n", x3.Bytes())
	//fmt.Printf("y3=%x\n", y3.Bytes())
	//fmt.Printf("z3=%x\n", z3.Bytes())
	return x3, y3, z3
}
func (curve *SM2CurveParam) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	//z inverse
	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)
	//x=x/z^2
	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	//y=y/z^3
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}
func (curve *SM2CurveParam) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}
func (curve *SM2CurveParam) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	z2 := new(big.Int).Mul(z, z)
	z2.Mod(z2, curve.P)
	z4 := new(big.Int).Mul(z2, z2)
	z4.Mod(z4, curve.P)
	az4 := new(big.Int).Mul(curve.A, z4)
	az4.Mod(az4, curve.P)
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, curve.P)
	tmpInt := new(big.Int).Set(x2)
	x2.Lsh(x2, 1)
	threeX2 := x2.Add(x2, tmpInt)
	threeX2.Mod(threeX2, curve.P)
	lamta1 := new(big.Int).Add(threeX2, az4)
	lamta1.Mod(lamta1, curve.P)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)
	fourX := new(big.Int).Lsh(x, 2)
	fourX.Mod(fourX, curve.P)
	lamta2 := new(big.Int).Mul(fourX, y2)
	lamta2.Mod(lamta2, curve.P)
	y4 := new(big.Int).Mul(y2, y2)
	y4.Mod(y4, curve.P)
	lamta3 := new(big.Int).Lsh(y4, 3)
	lamta3.Mod(lamta3, curve.P)
	lamta1Square := new(big.Int).Mul(lamta1, lamta1)
	lamta1Square.Mod(lamta1Square, curve.P)
	twoLamta2 := new(big.Int).Lsh(lamta2, 1)
	xdest := new(big.Int).Sub(lamta1Square, twoLamta2)
	if xdest.Sign() == -1 {
		xdest.Add(xdest, curve.P)
	}
	xdest.Mod(xdest, curve.P)
	lamta2SubXdest := new(big.Int).Sub(lamta2, xdest)
	if lamta2SubXdest.Sign() == -1 {
		lamta2SubXdest.Add(lamta2SubXdest, curve.P)
	}
	tmpInt = new(big.Int).Mul(lamta1, lamta2SubXdest)
	tmpInt.Mod(tmpInt, curve.P)
	ydest := new(big.Int).Sub(tmpInt, lamta3)
	if ydest.Sign() == -1 {
		ydest.Add(ydest, curve.P)
	}
	ydest.Mod(ydest, curve.P)
	zdest := new(big.Int).Mul(y, z)
	zdest.Lsh(zdest, 1)
	zdest.Mod(zdest, curve.P)
	return xdest, ydest, zdest

}
func (curve *SM2CurveParam) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	//scalar multiply opration,binary expansion method
	for _, vByte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if vByte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			vByte <<= 1
		}
	}
	return curve.affineFromJacobian(x, y, z)
}
func (curve *SM2CurveParam) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

var sm2P256 SM2CurveParam

func initSM2P256() {
	//ecdsa.PrivateKey{}
	//y^2=x^3+ax+b
	//sm2P256.CurveParams = &elliptic.CurveParams{Name: "SM2-P256"}
	sm2P256.Name = "SM2-P256"
	sm2P256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2P256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2P256.A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2P256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2P256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2P256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256.BitSize = 256
}

var initonce sync.Once

func SM2P256() Curve {
	initonce.Do(initSM2P256)
	//	elliptic.P256()
	return &sm2P256
}
