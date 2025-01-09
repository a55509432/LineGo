package goline

import (
	"fmt"

	"github.com/a55509432/linego/LineThrift"


	"encoding/base64"
	"encoding/json"

	// "github.com/tidwall/gjson"
)

type E2eeKeyData struct {
    mid    string
    keyId  int32
    privKey   string
    pubKey   string
    e2eeVersion int32
}

type Results struct {
	Result struct {
		Verifier  string `json:"verifier"`
		AuthPhase string `json:"authPhase"`
		Metadata  struct {
			EncryptedKeyChain string `json:"encryptedKeyChain"`
			PublicKey         string `json:"publicKey"`
			HashKeyChain      string `json:"hashKeyChain"`
		} `json:"matadata"`
	} `json:"result"`
	Timestamp string `json:"timestamp"`
}

func getResult(body []byte) (*Results, error) {
	var s = new(Results)
	err := json.Unmarshal(body, &s)
	return s, err
}

func (p *LINE) LoadService(showLog bool) (err error) {
	getprof, err := p.GetProfile()
	
	if err != nil {
		return err
	}
	//contact, err := p.GetContact(p.MID)
	// if err != nil {
	// 	return err
	// }
	p.MID = getprof.Mid
	if showLog {
		fmt.Println("\n##########  -[Login Successful]-  ##########")
		fmt.Println("DisplayName: ", getprof.DisplayName)
		fmt.Println("MID: ", p.MID)
		fmt.Println("AuthToken: ", p.AuthToken)
		fmt.Println("########## -[End of Information]- ##########")
		// p.SetTimelineHeaders()
		//s.AcquireEncryptedAccessToken()
	}
	p.Friends, err = p.GetAllContactIds()
	if err != nil {
		return err
	}
	p.Revision, err = p.PollService().GetLastOpRevision(p.ctx)
	// p.Revision = -1
	// p.Revision = 0
	if err != nil {
		return err
	}
	err = p.LoadE2EEKeys()
	return err
}



func (p *LINE) LoadE2EEKeys()  error {
	var e2eeKeys []*LineThrift.E2EEKey
    var e2eekeydata E2eeKeyData
	
	sqltext,err := p.DB.Prepare("select * from line_e2eekeydata where mid =? order by keyId desc")
	if err != nil {
		return err
	}
	rows, err := sqltext.Query(p.MID)
	if err != nil {
		return err
	}
    for rows.Next() {
        err = rows.Scan(&e2eekeydata.mid, &e2eekeydata.keyId, &e2eekeydata.privKey, &e2eekeydata.pubKey, &e2eekeydata.e2eeVersion)

		if err != nil {
			return err
		}
		privkey,err := base64.StdEncoding.DecodeString(e2eekeydata.privKey)
		if err != nil {
			return err
		}
		publickey,err := base64.StdEncoding.DecodeString(e2eekeydata.pubKey)
		if err != nil {
			return err
		}
		
		ek := &LineThrift.E2EEKey{Version:e2eekeydata.e2eeVersion,KeyId:e2eekeydata.keyId,PrivateKey:privkey,PublicKey:publickey}
		e2eeKeys = append(e2eeKeys,ek)
    }
	p.E2EEKey = e2eeKeys[0]
	p.E2EEKeys = e2eeKeys
	return nil
}

func (p *LINE) LoginWithAuthToken(authToken string) error {
	p.AuthToken = authToken
	return p.LoadService(true)
}

/*

func loginRequestQR(identity LineThrift.IdentityProvider, verifier string, secret []byte, e2ee int32) *LineThrift.LoginRequest {
	lreq := &LineThrift.LoginRequest{
		Type:             1,
		KeepLoggedIn:     true,
		IdentityProvider: identity,
		AccessLocation:   "127.0.0.1",
		SystemName:       SYSTEM_NAME,
		Verifier:         verifier,
		Secret:           secret,
		E2eeVersion:      e2ee,
	}
	return lreq
}

func (p *LINE) LoginWithQrCode(writeToFile bool) {
	tauth := p.AuthService()
	qrCode, err := tauth.GetAuthQrcode(p.ctx, true, SYSTEM_NAME, true)
	if err != nil {
		panic(err)
	}

	// by jay
	if writeToFile {
		fo, err := os.Create("url_login.txt")
		if err == nil {
			ss := qrCode.Verifier
			buf := make([]byte, 1024)
			buf = []byte(ss)
			_, err := fo.Write(buf[0:len(ss)])
			if err == nil {
				fo.Close()
			}
		}
	}
	p_key := GenerateAsymmetricKeypair()
	secret_query := CreateSecretQuery(p_key.PublicKey)
	fmt.Println("line://au/q/" + qrCode.Verifier + "?secret=" + secret_query + "&e2eeVersion=1")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", LINE_HOST_DOMAIN+LINE_CERTIFICATE_PATH, nil)
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("X-Line-Application", p.AppName)
	req.Header.Set("X-Line-Access", qrCode.Verifier)
	p.AuthToken = qrCode.Verifier
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	x, _ := getResult([]byte(body))
	iR := x.Result
	_verifier := iR.Verifier
	loginZ := p.LoginZService()
	loginReq := loginRequestQR(1, _verifier, []byte{}, 0)
	resultz, err := loginZ.LoginZ(p.ctx, loginReq)
	if err != nil {
		panic(err)
	}
	p.LoginWithAuthToken(resultz.AuthToken)
}
*/
