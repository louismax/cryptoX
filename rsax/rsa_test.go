package rsax

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"testing"
)

var (
	publicPKCS1 = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4//8F2TVtGTU18XAdbJ4O+S8D+YrtQOepDnAyRMli52NQPbf4e41
XprsIQYZ8qkbRjmLCTXI+Pz5g5AZZXVXQ284OY0OUyS5L28SlEXxTyFuv/jHtvt1
WvHOtMPXL6epyenvo2OAIEP7fAVQjyftWE9w+x1A01J5QOlWruc4M15ewkp5Dsyj
fjNF5MG51wSmcWsGCAIZ0POPNrvf/pYtaWq/4eK6GJAlJ+oytaaZBE0T+MpYoL2j
k6ranOYqPK7LVLMy3txRIJMtpjjb+Dc2SwV3tIeYKwuYu64gf6FiQjHwpSEFQ+CF
MdHYYEoxIgt8W1xB3SGInV6d5HZ9f/wLWwIDAQAB
-----END RSA PUBLIC KEY-----`

	privatePKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4//8F2TVtGTU18XAdbJ4O+S8D+YrtQOepDnAyRMli52NQPbf
4e41XprsIQYZ8qkbRjmLCTXI+Pz5g5AZZXVXQ284OY0OUyS5L28SlEXxTyFuv/jH
tvt1WvHOtMPXL6epyenvo2OAIEP7fAVQjyftWE9w+x1A01J5QOlWruc4M15ewkp5
DsyjfjNF5MG51wSmcWsGCAIZ0POPNrvf/pYtaWq/4eK6GJAlJ+oytaaZBE0T+MpY
oL2jk6ranOYqPK7LVLMy3txRIJMtpjjb+Dc2SwV3tIeYKwuYu64gf6FiQjHwpSEF
Q+CFMdHYYEoxIgt8W1xB3SGInV6d5HZ9f/wLWwIDAQABAoIBAQCAE9m6DoPaDVZf
S5Aczb+q7YgTalodGkZwvJyml6HctwmVd9k2YokKdv60YmgLH6HZphOLffJCpGFJ
3ZXWn78Ae6ba9XkZjaSVl9CZCF1Q9VfwcUFHciRvjSxv8R+dfpLrgQWEBC4Ccg4A
kj+521UB6cZu2fUDgO3qX+m44Nx6RbYW0FXfH84h8J/92X5192YnFw7n1BHZ3uIk
TkMr0+a7e1VqyjgfyoDrW0c8qEN5/UN0DzShXQuJtXfvZ17z61Rv8qXYzIVPHFTA
rKCqtC5ke/R5OQ6Zz3yxGb5grgapDgn9WJX03k9NSPGk6Wvv1c+2ukgbOOSmB3of
2tjj5lepAoGBAP/TaBEbkT3jvisIh8x0NjssWcF0IOWv5FECv4iIeEcychbSGftU
/xY6gb2Hki+AkCjHTID0hG1MRBC+pXcBlFaNAPecJiyPV5WQVxPyTq/AEcYevk0y
ojugQmPA0YO8P3VuigETjg0Ph67XyHO8hjtlrFhAdy4P0Ge+mqskMsFPAoGBAOQn
ulPCp+LzyUQQg77Xe7Q+zsNJ3WUuTRwfKd7+vgnu45IQoMo1qlK0uF9Ra/4wi706
KkoD5dhO+VqYncsp16K99BkmT2FoXlQl3afKWdzwDl5K58IYSyrT7xUIi8wWpECD
tZGaTStccRGQm32KAFZPjLiZUFNCUpxCrpGiqBo1AoGBAOdmwms3FFl29zzVqoA1
XhiINWfXMyqPv2XHpphJWQKNjsU1pmrApzvkEBbv2js9fyhjnb/HbUGwCqFa0TCk
LRlc0dMnWyBTSFXxCdLxClvO0ET06g3KDxUAEQ1KDDmsvXnrUslGduc5dPGiHZ8S
mBiCDzKEnUj85PXyYtULGR3hAoGAfkuXkwIv2SvF/818gEncClyyK9xZl8bXnHeL
wAsXu3vnsVVPDGBEll+/p9P0idLpp6fo/OvHccPVuFa/ElVpLocj9kAEtREHFmGX
n2gd8nVYHs4sGH9GLMEAmY4PhLwL1EKUYbMegKA9XtHDoOyhXyXN6enEUzJldGZd
J/T4RPkCgYBn3fqFtxOfV7ZxMxbivbz15RDaZ0k7k6c7Sf/HafDOL+VTrCi6lIXf
/dGjW0FdbTxmIQSMAe5fVEqzFaNWz//gPNWrHRDikzfy9jIKDe/nxV0lEOYXPmGj
bdz/NH6klplarq02xmXk6pwxd11bfq3AvckrUdjywiRfGw6C1+bO+w==
-----END RSA PRIVATE KEY-----`

	privatePKCS8 = `MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCIuzNbQBkiThGSEdK9zAsGOePyRM6TFTTsohOowXoK4cRbyVUg5GjmNSvf4CPsNcu/AjXxtfpeYX20v48eCjVPFK3yQ4+MyAIzziq8WPiNFjFV89K/+8AT+JXVeGZvDr6H0LD+Ny2qGI7mDGm4Xa7JOjl60CRa8Hq+BrI4JQoDKzm+jKULkvtvh+O1N83YlD3NBH8WuIvtVtpPbk6ewK22HaICqiED0WP9moJ5guGkySwEEFPeU+RKubId/1b+Uy+Q2AuYeyr9oWV0+jjkbgAg/STJXk9ZHQLld0wbREhnHJx/5DqRrmSpsap1Rqy5LvNhnyM25TIB7zu5QlXaxos7AgMBAAECggEBAIhEoXtI14PD8Gj2UGSNzVLoMRBLmOEnWnaXVSZzpJDhzpN3hNriKNV9mntlZAfO2X9E0cRSi/KyENkprJXQsK5eurlesdspnmBJEXhi51udCZBTDu/9E8ITliiI9PWr6SFsUGkbTuxdy1TkfBydaUvtNkn61LC5SGrIO6gO6fqbDdhcCFwe3Ct9EhH1vMbJu4I4FtLJ9yoiH8QgZGo49M6aTcyUcBtUulUqBAJV9wnYz9Jdsm8AUZxBKoHLjo80+YJVuwSRfLjb3BPqce+2BWmE7YIFCtawBVGJ35ALb+mvftSZZDuYDR95EWEe8qNRq8nCA+/n4DqbPcpF5nGhENkCgYEAvmGNTxYUOchl5PZ3jh04XMqKrkxXKGcGZmYJ7hRzRDKDFn7fbi+FfM9AfZwUlrz3rWCs+KnlcRHsrNY4lxPUXTdFXRyr47WbupKyULpq+BRXhsarZl+V9/CBr7rnewasqqtZSbBlQ2uDTHuTrib+GsXTgtKU7Wf6g/Qgeq142acCgYEAt9vO7nP8vB4BYAazjgluxQVctZ8MMQWeEALmPRsZCkXTGe/bwN2lI42T4KPOkqXwxfjKkIC+k8hWJ+e0wAXS4TMVNtE0fl47QjYkx/0USNIFqubhWDPRgTuBUeIi1WA4WVHJ11lCarsZA7CRiO1dPtSc31W63X11paz/VKekzE0CgYAy/kotTsqoF4dDZsjrJeR85jtzKDuINOA/+UDbplqhf64hDmamStBEd/bcLjxNi9wDcouiJ0+vk4+DU/XgcY1GUpGfuRhJa9GEjdp5SRVx0XEIRpqOVzgCK0dxXGy4RTdml3LZDAhzoI6Qo+EQmp0haq+WsPT3CgzN30v70A84rQKBgHtsoNasoF48mlm3RfQ02tqCRgFamtmR1tES0TL2LPIbe6JuxYwMft6GHV5xOKxzn1WXNYyaENWuaD/zqQA7KJyrKTOab23hnlBNfpWOjH5yFwHqah5G8v6ZTrAEabPqGwnDAQeC0TZLEXjLoHdWOQGDwyeeKoqjvUWSA/n1bIkFAoGBAL5PSCpW5HhVidNqXRvr08IhSO9XpqV6yiu/M+UarFwKR0jwXicQhwGHXOwALQQmmhD+E3FgRi9AxqOpOEF37xxnHYwYqjbzsgZsNzyEFBmS/ZaZcnCihbejbSltRVXKu7WFpk1OZoQXiLXVSAfhh4JL4mlC40hu31e9i1pf1H61`
	pubKeyPKCS8  = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiLszW0AZIk4RkhHSvcwLBjnj8kTOkxU07KITqMF6CuHEW8lVIORo5jUr3+Aj7DXLvwI18bX6XmF9tL+PHgo1TxSt8kOPjMgCM84qvFj4jRYxVfPSv/vAE/iV1Xhmbw6+h9Cw/jctqhiO5gxpuF2uyTo5etAkWvB6vgayOCUKAys5voylC5L7b4fjtTfN2JQ9zQR/FriL7VbaT25OnsCtth2iAqohA9Fj/ZqCeYLhpMksBBBT3lPkSrmyHf9W/lMvkNgLmHsq/aFldPo45G4AIP0kyV5PWR0C5XdMG0RIZxycf+Q6ka5kqbGqdUasuS7zYZ8jNuUyAe87uUJV2saLOwIDAQAB`

	label = "louisMax"
)

func TestFormatPrivateKey(t *testing.T) {
	t.Log(FormatPrivateKey(privatePKCS8))
}

func TestFormatPublicKey(t *testing.T) {
	t.Log(FormatPublicKey(pubKeyPKCS8))
}

func TestRsaEncryptAndDecrypt(t *testing.T) {
	originData := "https://github.com/"
	log.Println("数据：", originData)
	encryptData, err := RsaEncrypt(PKCS8, []byte(originData), FormatPublicKey(pubKeyPKCS8))
	if err != nil {
		log.Println("RsaEncrypt:", err)
		return
	}
	log.Printf("encrypt：%s\n", base64.StdEncoding.EncodeToString(encryptData))

	origin, err := RsaDecrypt(PKCS8, encryptData, FormatPrivateKey(privatePKCS8))
	if err != nil {
		log.Println("RsaDecrypt:", err)
		return
	}
	log.Println("decrypt:", string(origin))
}

func TestRsaEncryptOAEPAndDecryptOAEP(t *testing.T) {
	originData := "https://github.com/"
	log.Println("数据：", originData)
	encryptData, err := RsaEncryptOAEP(sha256.New(), PKCS1, publicPKCS1, []byte(originData), []byte(label))
	if err != nil {
		log.Println("RsaEncrypt:", err)
		return
	}
	base64EncryptData := base64.StdEncoding.EncodeToString(encryptData)
	log.Println("base64EncryptData:", base64EncryptData)

	bytes, err := base64.StdEncoding.DecodeString(base64EncryptData)
	if err != nil {
		log.Println("base64.StdEncoding.DecodeString:", err)
		return
	}
	origin, err := RsaDecryptOAEP(sha256.New(), PKCS1, privatePKCS1, bytes, []byte(label))
	if err != nil {
		log.Println("RsaDecrypt:", err)
		return
	}
	log.Println("decrypt:", string(origin))
}
