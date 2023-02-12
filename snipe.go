package main

import (
	"fmt"
	"strings"
	"io/ioutil"
	"strconv"
	"net/url"
	"net/http"
	"time"
	"net/http/httputil"
	"flag"
)

type Request struct {
    Method string
	Path string
	ProtoMinor int
	ProtoMajor int
	Headers map[string]string
    Body string
}

type Config struct {
	Timeout int
	Proxy string
	SSL bool
	Filename string	
	Fuzz string
	Payloads string
	Simultaneous bool
}

//snipe.go -r request1 -f FUZZ -w payloads
func main() {
	cfg := getFlags()
	raw, err := ReadFileToString(&cfg.Filename)
	
	if err != nil {
		panic(err)
	}
	if cfg.Payloads != "" {
		p, err := ReadFileToString(&cfg.Payloads)
		if err != nil {
			panic(err)
		}
		payloads := strings.Split(p,"\n")
		if cfg.Simultaneous {
			for _, payload := range payloads{
				raw2 := strings.Replace(raw,cfg.Fuzz,payload,-1)
				req := ParseToStruct(&raw2)
				_, err = MakeRequest(req,cfg)
			}
		} else { //one at-a-time, more common
			var raws []string
			var replaced string
			fuzzCount := strings.Count(raw,cfg.Fuzz)
			for _, payload := range payloads{
				for i:=1;i<fuzzCount+1;i++ {
					replaced = ReplaceNthInstance(raw,cfg.Fuzz,i,payload)
					raws = append(raws,replaced)
				}
			}
			for _, r := range raws {
				req := ParseToStruct(&r)
				_, err = MakeRequest(req,cfg)
			}
		}
	}

}

func getFlags() *Config {
	cfg := Config{}
	flag.StringVar(&cfg.Filename, "r", "", "filename of raw request copied from Burp")
	flag.IntVar(&cfg.Timeout, "t", 0, "timeout (in seconds)")
	flag.StringVar(&cfg.Proxy, "P", "", "proxy")
	flag.BoolVar(&cfg.SSL, "n", true, "disable ssl")
	flag.StringVar(&cfg.Fuzz, "f", "", "FUZZ string to be replaced from raw request file")
	flag.StringVar(&cfg.Payloads, "w", "", "Payloads wordlist")
	flag.BoolVar(&cfg.Simultaneous, "S", false, "Insert payload into all FUZZ spots (as opposed to one at-a-time)")
	flag.Parse()
	return &cfg
}

func ReadFileToString(filename *string) (string, error) {
	b, err := ioutil.ReadFile(*filename)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ReplaceNthInstance(raw string, fuzz string, n int, payload string) string {
	count := 0
	for i := 0; i < len(raw); i++ {
		if len(raw) - i < len(fuzz) {break} //avoid error
		// check if the current character matches the substring
		if raw[i:i+len(fuzz)] == fuzz {
			count++
			// check if the current instance is the nth instance
			if count == n {
				// replace the nth instance with the replace string
				raw = raw[:i] + payload + raw[i+len(fuzz):]
				break
			}
		}
	}
	// all other instances are replaced with an empty string
	return strings.Replace(raw, fuzz, "", -1)
}

func ParseToStruct(raw *string) *Request {
	lines := strings.Split(*raw, "\n")
	parts := strings.Split(lines[0], " ")
	method := parts[0]
	path := parts[1]
	proto := parts[2]
	parts = strings.Split(proto, "/")
	var protoMajor,protoMinor int
	if strings.Contains(parts[1],".") {
		parts = strings.Split(parts[1], ".")
		protoMajor, _ = strconv.Atoi(parts[0])
		protoMinor, _ = strconv.Atoi(parts[1])
	} else {
		protoMajor, _ = strconv.Atoi(parts[1])
		protoMinor = 0
	}
	headers := make(map[string]string)
	for _, line := range lines[1 : len(lines)] {
		if (strings.TrimSpace(line) == ""){
			break
		}
		kv := strings.SplitN(line, ":", 2)
		headers[kv[0]] = strings.TrimSpace(kv[1])
	}
	var body string
	if strings.Contains(*raw,"\n\n") {
		body = lines[len(lines)-1]
	}

	fmt.Println()
	fmt.Println(body)
	
	req := Request{}
	req.Method = method
	req.Path = path
	req.ProtoMajor = protoMajor
	req.ProtoMinor = protoMinor
	req.Headers = headers
	req.Body = body

	return &req
}

func MakeRequest(req *Request,cfg *Config) (*http.Response, error) {
	proto := "http://"
	if cfg.SSL == true {proto = "https://"}
	httpReq, err := http.NewRequest(req.Method, proto + req.Headers["Host"] + req.Path, strings.NewReader(req.Body))
	if err != nil {
		panic(err)
	}
	for k,v := range req.Headers {
		httpReq.Header.Set(k,v)
	}
	httpReq.ProtoMajor = req.ProtoMajor
	httpReq.ProtoMinor = req.ProtoMinor
	
	httpReq.Header.Set("Content-Length", strconv.Itoa(len(req.Body)))

	client := http.Client{}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			panic(err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}/*default? else {
		proxy := http.ProxyFromEnvironment()
		client.Transport = &http.Transport{Proxy: proxy}
	}*/

	if cfg.Timeout != 0 {
		client.Timeout = time.Second * time.Duration(cfg.Timeout)
	} else {
		client.Timeout = time.Second * 1
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	
	fmt.Println("Request:")
	reqDump, err := httputil.DumpRequest(httpReq, true)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(reqDump))
	fmt.Println("Response:")
	fmt.Println(resp.Status)
	for key, value := range resp.Header {
		fmt.Printf("%s: %s\n", key, value[0])
	}
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("\n" + string(body))
	return resp, err
}