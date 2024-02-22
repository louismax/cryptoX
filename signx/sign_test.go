package signx

import (
	"github.com/louismax/cryptoX/pemx"
	"github.com/louismax/cryptoX/rsax"
	"testing"
)

var (
	privatePKCS8 = `MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCIuzNbQBkiThGSEdK9zAsGOePyRM6TFTTsohOowXoK4cRbyVUg5GjmNSvf4CPsNcu/AjXxtfpeYX20v48eCjVPFK3yQ4+MyAIzziq8WPiNFjFV89K/+8AT+JXVeGZvDr6H0LD+Ny2qGI7mDGm4Xa7JOjl60CRa8Hq+BrI4JQoDKzm+jKULkvtvh+O1N83YlD3NBH8WuIvtVtpPbk6ewK22HaICqiED0WP9moJ5guGkySwEEFPeU+RKubId/1b+Uy+Q2AuYeyr9oWV0+jjkbgAg/STJXk9ZHQLld0wbREhnHJx/5DqRrmSpsap1Rqy5LvNhnyM25TIB7zu5QlXaxos7AgMBAAECggEBAIhEoXtI14PD8Gj2UGSNzVLoMRBLmOEnWnaXVSZzpJDhzpN3hNriKNV9mntlZAfO2X9E0cRSi/KyENkprJXQsK5eurlesdspnmBJEXhi51udCZBTDu/9E8ITliiI9PWr6SFsUGkbTuxdy1TkfBydaUvtNkn61LC5SGrIO6gO6fqbDdhcCFwe3Ct9EhH1vMbJu4I4FtLJ9yoiH8QgZGo49M6aTcyUcBtUulUqBAJV9wnYz9Jdsm8AUZxBKoHLjo80+YJVuwSRfLjb3BPqce+2BWmE7YIFCtawBVGJ35ALb+mvftSZZDuYDR95EWEe8qNRq8nCA+/n4DqbPcpF5nGhENkCgYEAvmGNTxYUOchl5PZ3jh04XMqKrkxXKGcGZmYJ7hRzRDKDFn7fbi+FfM9AfZwUlrz3rWCs+KnlcRHsrNY4lxPUXTdFXRyr47WbupKyULpq+BRXhsarZl+V9/CBr7rnewasqqtZSbBlQ2uDTHuTrib+GsXTgtKU7Wf6g/Qgeq142acCgYEAt9vO7nP8vB4BYAazjgluxQVctZ8MMQWeEALmPRsZCkXTGe/bwN2lI42T4KPOkqXwxfjKkIC+k8hWJ+e0wAXS4TMVNtE0fl47QjYkx/0USNIFqubhWDPRgTuBUeIi1WA4WVHJ11lCarsZA7CRiO1dPtSc31W63X11paz/VKekzE0CgYAy/kotTsqoF4dDZsjrJeR85jtzKDuINOA/+UDbplqhf64hDmamStBEd/bcLjxNi9wDcouiJ0+vk4+DU/XgcY1GUpGfuRhJa9GEjdp5SRVx0XEIRpqOVzgCK0dxXGy4RTdml3LZDAhzoI6Qo+EQmp0haq+WsPT3CgzN30v70A84rQKBgHtsoNasoF48mlm3RfQ02tqCRgFamtmR1tES0TL2LPIbe6JuxYwMft6GHV5xOKxzn1WXNYyaENWuaD/zqQA7KJyrKTOab23hnlBNfpWOjH5yFwHqah5G8v6ZTrAEabPqGwnDAQeC0TZLEXjLoHdWOQGDwyeeKoqjvUWSA/n1bIkFAoGBAL5PSCpW5HhVidNqXRvr08IhSO9XpqV6yiu/M+UarFwKR0jwXicQhwGHXOwALQQmmhD+E3FgRi9AxqOpOEF37xxnHYwYqjbzsgZsNzyEFBmS/ZaZcnCihbejbSltRVXKu7WFpk1OZoQXiLXVSAfhh4JL4mlC40hu31e9i1pf1H61`
)

func TestRsaSign(t *testing.T) {
	ps := rsax.FormatPrivateKey(privatePKCS8)

	P, err := pemx.DecodePrivateKey([]byte(ps))
	if err != nil {
		t.Error(err)
	}

	params := `data={"cooper_company":"alipay","school_org_id":"1004000003"}&partnerId=9772202088917843&service=com.qkt.face.school.enroll.face.sign.query&timestamp=1708588486151`

	signStr, err := RsaSign([]byte(params), "RSA2", P)
	if err != nil {
		t.Error(err)
	}
	t.Logf("签名:%s", signStr)
}
