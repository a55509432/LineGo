package goline

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	rand2 "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/url"
	"strings"
	"regexp"
    "strconv"
	"time"

	"github.com/a55509432/linego/LineThrift"

	curve "github.com/miguelsandro/curve25519-go/axlsign"
)


func UnicodeEmojiCode(s string) string {
	ret := ""
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if len(string(rs[i])) == 4 {
			u := `[\u` + strconv.FormatInt(int64(rs[i]), 16) + `]`
			ret += u
 
		} else {
			ret += string(rs[i])
		}
	}
	return ret
}


func UnicodeEmojiDecode(s string) string {
    //emoji表情的数据表达式
    re := regexp.MustCompile("\\[[\\\\u0-9a-zA-Z]+\\]")
    //提取emoji数据表达式
    reg := regexp.MustCompile("\\[\\\\u|]")
    src := re.FindAllString(s, -1)
    for i := 0; i < len(src); i++ {
        e := reg.ReplaceAllString(src[i], "")
        p, err := strconv.ParseInt(e, 16, 32)
        if err == nil {
            s = strings.Replace(s, src[i], string(rune(p)), -1)
        }
    }
    return s
}


type resource struct {
	E int8 `json:"E"`
	S int8  `json:"S"`
	ProductId string `json:"productId"`
	ResourceType string  `json:"resourceType"`
	SticonId string  `json:"sticonId"`
	Version int8  `json:"version"`
}

type DecryptMetaData struct {
	KeyMaterial string  `json:"keyMaterial"`
	FileName string  `json:"fileName"`
}

type DecryptLocationData struct {
	Location struct {
		Address string `json:"address"`
		Latitude float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	}  `json:"location"`
}

type DecryptTextData struct {
	Text string `json:"text"`
	
	REPLACE struct {
		Sticon struct {
			Resources []resource `json:"resources"`
		} `json:"sticon"`
	} `json:"REPLACE"`
}

func randomBytes(size int) []uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	var High int = 255
	var seed = make([]uint8, size)
	for i := 0; i < len(seed); i++ {
		seed[i] = uint8(rand.Int() % (High + 1))
	}
	return seed
}

func GenerateAsymmetricKeypair() curve.Keys {
	seed := randomBytes(32)
	return curve.GenerateKeyPair(seed)
}

func GenerateSharedKey(privateKey, publicKey []byte) (sharedKey []byte, err error) {
	if len(privateKey) != 32 || len(publicKey) != 32 {
		return sharedKey, fmt.Errorf("invalid length of key pair")
	}
	sharedKey = curve.SharedKey(privateKey, publicKey)
	return sharedKey, nil
}

func CreateSecretQuery(PublicKey []uint8) string {
	return url.QueryEscape(base64.StdEncoding.EncodeToString(PublicKey))
}

func HalfXorData(data []byte) []byte {
	lenbuf := len(data)
	res := make([]byte, lenbuf/2)
	for i := 0; i < lenbuf/2; i++ {
		res[i] = data[i] ^ data[lenbuf/2+i]
	}
	return res
}

func aesCBCEncrypt(encodeBytes, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	encodeBytes = PKCS7Padding(encodeBytes, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(encodeBytes))
	blockMode.CryptBlocks(crypted, encodeBytes)
	return crypted, nil
}

func aesCBCDecrypt(encryptedData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)
	encryptedData, err = PKCS7UnPadding(encryptedData)
	if err != nil {
		return []byte{}, err
	}
	return encryptedData, nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	if (length-unpadding) < 0 || (length-unpadding) >= len(origData) {
		return nil, fmt.Errorf("invalid length: %d %d", length, unpadding)
	}
	return origData[:(length - unpadding)], nil
}

func EncryptPassword(passwd string, keypair curve.Keys, mynonce []uint8, public_key, nonce string) (string, error) {
	publicKey, _ := base64.StdEncoding.DecodeString(public_key)
	exchangedNonce, _ := base64.StdEncoding.DecodeString(nonce)
	sharedSecret, err := GenerateSharedKey(keypair.PrivateKey, publicKey)
	if err != nil {
		return "", err
	}
	masterKey := sha256.Sum256(append([]byte("master_key"), append(sharedSecret, append(mynonce, exchangedNonce...)...)...))
	keyAndIv := sha256.Sum256(append([]byte("aes_key"), masterKey[:]...))
	hmacKey := sha256.Sum256(append([]byte("hmac_key"), masterKey[:]...))
	ciphertext, err := aesCBCEncrypt([]byte(passwd), keyAndIv[:16], keyAndIv[16:32])
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(ciphertext)
	return base64.StdEncoding.EncodeToString(append(ciphertext, h.Sum(nil)...)), nil
}

func createPinCode() (string, error) {
	pin, err := rand2.Int(rand2.Reader, big.NewInt(999999))
	if err != nil {
		return "", err
	}
	// padding
	return fmt.Sprintf("%06d", pin), nil
}

func xor(data []byte) (r []byte) {
	length := len(data) / 2
	r = make([]byte, length)
	for i := 0; i < length; i++ {
		r[i] = data[i] ^ data[length+i]
	}
	return r
}

func GetSignature(authKey string, rev int) string {
	split := strings.SplitN(authKey, ":", 2)
	if len(split) > 3 || len(split) < 2 {
		return ""
	}
	currentMillis := time.Now().UTC().UnixNano() / int64(time.Millisecond)
	var key []byte
	var lastID = len(split) - 1
	key, _ = base64.StdEncoding.DecodeString(split[lastID])
	msg, meta := "", ""
	if rev == 1 { // androidlite
		msg = fmt.Sprintf("issuedTo: %s\niat: %d\n", split[0], currentMillis)
		meta = base64.StdEncoding.EncodeToString([]byte("type: YWT\nalg: HMAC_SHA1\n"))
	} else { // android
		msg = fmt.Sprintf("iat: %d\n", currentMillis)
		meta = ""
	}
	split[lastID] = base64.StdEncoding.EncodeToString([]byte(msg)) + "." + meta
	//
	h := hmac.New(sha1.New, key)
	h.Write([]byte(split[lastID]))
	split[lastID] += "." + base64.StdEncoding.EncodeToString(h.Sum(nil))
	return strings.Join(split, ":")
}

func byte2int(b []byte) int32 {
	var i int32
	i = 0
	for _,k := range b {
		i = 256 * i + int32(k)
	}
	return i
}


// def generateAAD(self, a, b, c, d, e=2, f=0):
//         aad = b""
//         aad += a.encode()
//         aad += b.encode()
//         aad += bytes(self.getIntBytes(c))
//         aad += bytes(self.getIntBytes(d))
//         aad += bytes(self.getIntBytes(e))  # e2ee version
//         aad += bytes(self.getIntBytes(f))  # content type
//         return aad

func Int8ToBytes(n int8) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func Int32ToBytes(x int32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func GenerateAAD(a string, b string, c int32, d int32, e int32, f int8) []byte {
	return BytesCombine([]byte(a), []byte(b), Int32ToBytes(c), Int32ToBytes(d), Int32ToBytes(e), Int8ToBytes(f))
	// aad = append(aad,[]byte(b))

}

func (p *LINE) getE2EELocalPublicKey(mid string, keyId int32, totype LineThrift.MIDType) []byte {
	if totype == 0 {
		if keyId != -1 {
			flag,key := p.GetCacheKey(mid,"-1",keyId)
			if flag {
				return key
			} else{
				res,err := p.NegotiateE2EEPublicKey(mid)
				fmt.Println(err)
				b64key := base64.StdEncoding.EncodeToString(res.PublicKey.KeyData)
				flag = p.SaveCacheKey(mid,"-1",keyId,b64key)
				return res.PublicKey.KeyData
			}
			
		} else {
			return []byte{}
		}
	} else {
		if keyId != -1 {
			flag,key := p.GetCacheKey("-1",mid,keyId)
			if flag {
				return key
			} else{
				res,err := p.GetLastE2EEGroupSharedKey(2,mid)
				fmt.Println(res)
				creator := res.Creator
				creatorKeyId := res.CreatorKeyId
				encryptedSharedKey := res.EncryptedSharedKey
				selfprikey := p.E2EEKey.PrivateKey
				creatorKey := p.getE2EELocalPublicKey(creator, creatorKeyId, LineThrift.MIDType_USER)
				fmt.Println("888888888888")
				fmt.Println(creatorKey)
				aeskey,_ := GenerateSharedKey(selfprikey, creatorKey)
				aes_key := sha256.Sum256(BytesCombine(aeskey, []byte("Key")))
				iv := sha256.Sum256(BytesCombine(aeskey[:], []byte("IV")))
				aes_iv := xor(iv[:])

				decrypted,err := aesCBCDecrypt(encryptedSharedKey,aes_key[:],aes_iv)
				if err == nil {
					b64key := base64.StdEncoding.EncodeToString(decrypted)
					flag = p.SaveCacheKey("-1",mid,keyId,b64key)
					return decrypted
				} else{
					return []byte{}
				}
			}
		} else {
			return []byte{}
		}
		
	}

}



func (p *LINE) DecryptE2EETextMessage(msg *LineThrift.Message, isself bool) (string,string) {

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}
	
	
	

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)

		var dt DecryptTextData
		json.Unmarshal([]byte(d), &dt)

		if msg.ContentMetadata["STICON_OWNERSHIP"] == "" {
			fmt.Println(dt.Text)
			return dt.Text,""
		} else {
			fmt.Println(dt.Text)
			replacebyte,_ := json.Marshal(dt.REPLACE)
			replacestr := string(replacebyte)
			fmt.Println(replacestr)
			return dt.Text,replacestr
		}
	} else{
		fmt.Println(pubK)
		return "",""
	}
	
}

func (p *LINE) DecryptE2EEImageMessage(msg *LineThrift.Message, isself bool) (string, string){

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)
		fmt.Println("99999999999")
		fmt.Println(d)
		var dt DecryptMetaData
		json.Unmarshal([]byte(d), &dt)
		fmt.Println(dt)
		return dt.KeyMaterial,dt.FileName
	} else{
		return "",""
	}
}

func (p *LINE) DecryptE2EEVideoMessage(msg *LineThrift.Message, isself bool) (string, string){

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)
		fmt.Println("99999999999")
		fmt.Println(d)
		var dt DecryptMetaData
		json.Unmarshal([]byte(d), &dt)
		fmt.Println(dt)
		return dt.KeyMaterial,dt.FileName
	} else{
		return "",""
	}
}

func (p *LINE) DecryptE2EEAudioMessage(msg *LineThrift.Message, isself bool) (string, string){

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)
		fmt.Println("99999999999")
		fmt.Println(d)
		var dt DecryptMetaData
		json.Unmarshal([]byte(d), &dt)
		fmt.Println(dt)
		return dt.KeyMaterial,dt.FileName
	} else{
		return "",""
	}
}

func (p *LINE) DecryptE2EEFileMessage(msg *LineThrift.Message, isself bool) (string, string){

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)
		fmt.Println("99999999999")
		fmt.Println(d)
		var dt DecryptMetaData
		json.Unmarshal([]byte(d), &dt)
		fmt.Println(dt)
		return dt.KeyMaterial,dt.FileName
	} else{
		return "",""
	}
}

func (p *LINE) DecryptE2EELocationMessage(msg *LineThrift.Message, isself bool) string{

	senderKeyId := byte2int(msg.Chunks[3])
	receiverKeyId := byte2int(msg.Chunks[4])

	
	privK := p.E2EEKey.PrivateKey
	pubK := p.E2EEKey.PublicKey
	

	fmt.Println(msg)

	if msg.ToType  == 0 {
		if isself {
			pubK = p.getE2EELocalPublicKey(msg.To,receiverKeyId, msg.ToType )
		} else {
			pubK = p.getE2EELocalPublicKey(msg.From_,senderKeyId, msg.ToType )
		}
	} else {
		privK = p.getE2EELocalPublicKey(msg.To, receiverKeyId, msg.ToType )
		if msg.From_ != p.MID {
			pubK = p.getE2EELocalPublicKey(msg.From_, senderKeyId,LineThrift.MIDType_USER )
		}
	}

	if msg.ContentMetadata["e2eeVersion"] == "2" {
		d := p.DecryptE2EEMessageV2(msg.To, msg.From_, msg.Chunks, privK, pubK, msg.ContentType)
		fmt.Println("99999999999")
		fmt.Println(d)
		var dt DecryptLocationData
		json.Unmarshal([]byte(d), &dt)
		// fmt.Println(dt)
		replacebyte,_ := json.Marshal(dt.Location)
		replacestr := string(replacebyte)
		return replacestr
	} else{
		return ""
	}
}


func BytesCombine(pBytes ...[]byte) []byte {
    return bytes.Join(pBytes, []byte(""))
}

func (p *LINE) DecryptE2EEMessageV2(to string, from_ string, chunks [][]byte, privk []byte, pubk []byte, contenttype LineThrift.ContentType) string {

	specVersion := int32(2)
	aeskey,_ := GenerateSharedKey(privk, pubk)
	gcmKey := sha256.Sum256(BytesCombine(aeskey, chunks[0], []byte("Key")))
	add := GenerateAAD(to, from_, byte2int(chunks[3]), byte2int(chunks[4]), specVersion, int8(contenttype))

	tagsize := 12

	block, err := aes.NewCipher(gcmKey[:])
	if err != nil {
		fmt.Println(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, tagsize)
	if err != nil {
		fmt.Println(err)
	}

	plaintext, err := aesgcm.Open(nil, chunks[2], chunks[1], add[:])
	fmt.Println(plaintext)
	return UnicodeEmojiCode(string(plaintext))


}