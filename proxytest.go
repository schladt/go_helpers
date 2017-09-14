//Test proxy connections
package main

import (
	"crypto/tls"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	URL = "https://google.com"
	UA  = "MyClient/1.0"
)

func main() {

	//get transport and client
	transport, httpClient := createTransportAndClient()

	//simple get test
	log.Printf("Testing NO PROXY: ")
	testRequest(httpClient)

	//find system proxies
	proxies, err := findProxies()
	if err != nil {
		log.Printf("Problem finding system proxies: %v", err)
	}

	for _, proxy := range proxies {
		//test with proxy
		url_i := url.URL{}
		url_proxy, _ := url_i.Parse("http://" + proxy)
		transport.Proxy = http.ProxyURL(url_proxy)

		log.Printf("Testing : " + proxy)
		testRequest(httpClient)
	}

}

func testRequest(httpClient http.Client) {

	//create request object
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		log.Fatal("Error creating request: ", err)
	}

	//set user-agent string
	req.Header.Set("User-Agent", UA)

	//make request
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Network error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	//read and parse response
	body, _ := ioutil.ReadAll(resp.Body)
	respString := string(body)
  log.Println(respString)
}

func createTransportAndClient() (*http.Transport, http.Client) {
	//create transport
	transport := &http.Transport{
		MaxIdleConns:       1,
		IdleConnTimeout:    1 * time.Second,
		DisableKeepAlives:  true,
		DisableCompression: true, //compression is handled manually
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		ProxyConnectHeader: http.Header{"User-Agent": []string{UA}},
	}

	//create httpClient
	httpClient := http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	//function to keep headers during redirects
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return nil
		}
		if len(via) == 0 {
			return nil
		}
		for attr, val := range via[0].Header {
			req.Header[attr] = val
		}

		return nil
	}
	return transport, httpClient
}

func findProxies() ([]string, error) {

	//get all user profiles for this system
	users, err := registry.USERS.ReadSubKeyNames(1024)

	var proxies []string

	tempProxies := make(map[string]struct{})
	tempPacFiles := make(map[string]struct{})

	for _, userName := range users {
		k, err := registry.OpenKey(registry.USERS, userName+"\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer k.Close()

		proxyServer, _, _ := k.GetStringValue("ProxyServer")
		pacFile, _, _ := k.GetStringValue("AutoConfigUrl")

		if proxyServer != "" {
			tempProxies[proxyServer] = struct{}{}
		}

		if pacFile != "" {
			tempPacFiles[pacFile] = struct{}{}
		}
	}

	//process pacfiles
	for pacFile, _ := range tempPacFiles {
		resp, err := http.Get(pacFile)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		//read and parse response
		body, _ := ioutil.ReadAll(resp.Body)

		re := regexp.MustCompile("\"PROXY\\s(.*?)\"")
		matches := re.FindAllSubmatch(body, -1)

		for _, match := range matches {
			proxy := string(match[1])
			if proxy != "" && strings.ToLower(proxy) != "none" {
				tempProxies[proxy] = struct{}{}
			}
		}
	}

	//convert the temp maps into proper slices
	for proxy, _ := range tempProxies {
		proxies = append(proxies, proxy)
	}

	err = nil
	return proxies, err
}
