package rsax

import "strings"

// FormatPrivateKey 格式化普通应用秘钥(例如支付宝)
func FormatPrivateKey(privateKey string) (pKey string) {
	var buffer strings.Builder
	buffer.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	rawLen := 64
	keyLen := len(privateKey)
	raws := keyLen / rawLen
	temp := keyLen % rawLen
	if temp > 0 {
		raws++
	}
	start := 0
	end := start + rawLen
	for i := 0; i < raws; i++ {
		if i == raws-1 {
			buffer.WriteString(privateKey[start:])
		} else {
			buffer.WriteString(privateKey[start:end])
		}
		buffer.WriteByte('\n')
		start += rawLen
		end = start + rawLen
	}
	buffer.WriteString("-----END RSA PRIVATE KEY-----\n")
	pKey = buffer.String()
	return
}

// FormatPublicKey 格式化普通公钥(例如支付宝)
func FormatPublicKey(publicKey string) (pKey string) {
	var buf strings.Builder
	buf.WriteString("-----BEGIN PUBLIC KEY-----\n")
	rawLen := 64
	keyLen := len(publicKey)
	raws := keyLen / rawLen
	temp := keyLen % rawLen
	if temp > 0 {
		raws++
	}
	start := 0
	end := start + rawLen
	for i := 0; i < raws; i++ {
		if i == raws-1 {
			buf.WriteString(publicKey[start:])
		} else {
			buf.WriteString(publicKey[start:end])
		}
		buf.WriteByte('\n')
		start += rawLen
		end = start + rawLen
	}
	buf.WriteString("-----END PUBLIC KEY-----\n")
	pKey = buf.String()
	return
}
