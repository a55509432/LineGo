package linego


import (
	"bytes"
	"io"
    "fmt"
    "golang.org/x/net/http2"
    "net/http"
	"net/url"
	"unsafe"
    _ "github.com/a55509432/linego/thriftlinego"
)
// Client contains everything necessary to connect to and interact with the Line API.
type Client struct {
    authtoken       string
    proxyurl        string               
	http           *http.Client
	http2           *http.Client
}

func NewClient(authtoken string,proxyurl string) *Client {
    
	proxyURL, _ := url.Parse(proxyurl)
	tr := &http.Transport{
        Proxy: func(req *http.Request) (*url.URL, error) {
            return proxyURL, nil
        },
    }
    tr2 := &http.Transport{
        Proxy: func(req *http.Request) (*url.URL, error) {
            return proxyURL, nil
        },
    }

	http2.ConfigureTransport(tr2)

	cli := &Client{
        authtoken: authtoken,
        proxyurl: proxyurl,
		http: &http.Client{Transport: tr},
		http2: &http.Client{Transport: tr2},
		
	}
	return cli
}

func (cli *Client) PostHttp2Request(_method string, url string , bodybyte []byte) {
	req, err := http.NewRequest(_method, url, bytes.NewBuffer([]byte(bodybyte)))
    if err != nil {
        panic(err)
    }

	req.Header.Set("accept", "application/x-thrift")
    req.Header.Set("content-type", "application/x-thrift; protocol=TCOMPACT")
	req.Header.Set("X-Line-Access", cli.authtoken)
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36")
	req.Header.Set("x-line-application", "ANDROID\t13.8.0\tAndroid OS\t10")
	req.Header.Set("x-lal", "zh-Hans_CN")
	req.Header.Set("x-lpv", "1")


    // 发送请求
    resp, err := cli.http.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
 
    // 读取响应内容
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
    fmt.Printf("response: %+v", resp)
    fmt.Printf("response: %x\n", data)
	fmt.Println("resp.ContentLength: ", resp.ContentLength)
	fmt.Println("resp.size: ",unsafe.Sizeof(resp))
}

func (cli *Client) GetProfile() {

    dps := DummyProtocolSerializer{name:"getProfile",protocol:4}
    x,_ := dps.tobytes()
    fmt.Println(x)
    cli.PostHttp2Request("POST","https://gws.line.naver.jp/S4",[]byte(x))
}

func (cli *Client) GetAllContactIds() {

    dps := DummyProtocolSerializer{name:"getAllContactIds",protocol:4}
    x,_ := dps.tobytes()
    fmt.Println(x)
    cli.PostHttp2Request("POST","https://gws.line.naver.jp/S4",[]byte(x))
}

func (cli *Client) AcquireEncryptedAccessToken(featureType int) {
    // if featureType == nil {
    //     featureType := 2
    // }
    dps := DummyProtocolSerializer{
        name:"acquireEncryptedAccessToken",
        data: [1][3]int{
            {8, 2, featureType},
        },
        protocol:4}
    x,_ := dps.tobytes()
    fmt.Println(x)
    cli.PostHttp2Request("POST","https://gws.line.naver.jp/S4",[]byte(x))
}