package modules

import (
	"flag"
	"log"
	"os"
	"sync"
)

var (
	I  Ivms
	wg sync.WaitGroup
)

func (I *Ivms) init() {
	flag.StringVar(&I.target, "u", "", "target you want fuck.")
	flag.StringVar(&I.targetFile, "f", "", "targets you want fuck.")
	flag.StringVar(&I.shellFile, "s", "", "shell file you want upload.")
	flag.IntVar(&I.timeout, "t", 5, "request timeout default is 5 second.")
	flag.BoolVar(&I.upload, "e", false, "direct fuck targets.")
	flag.BoolVar(&I.check, "c", true, "check target vuln.(default)")
	flag.Parse()
	I.vuln = false
	if I.target == "" && I.targetFile == "" {
		log.Fatalln("[*] just give single target with u parma or multi targets with parma f")
	}
	if I.target != "" && I.targetFile != "" {
		log.Fatalln("[*] just give single target with u parma or multi targets with parma f")
	}
	if I.targetFile != "" {
		I.loadTargetsFile()
	}
	if I.upload {
		if I.shellFile == "" {
			log.Fatalln("[*] pls specific a shell file if you want upload.")
		} else {
			if _, err := os.Stat(I.shellFile); err == nil {
				return
			} else if os.IsNotExist(err) {
				log.Fatalln("[*] shell file you give not exists.")
			} else {
				log.Fatalln("[*] shell file you give not exists.")
			}
		}
	}
}
