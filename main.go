package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/babolivier/go-doh-client"
	"github.com/oschwald/geoip2-golang"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	configfile = "config.yaml"
	homeDir string
	resolver doh.Resolver
	config Config
    Tree map[byte] *node = make(map[byte] *node)
    domainFile = "list.txt"
    mmdbFile = "GeoLite2-Country.mmdb"
    domainFilePtr *os.File
    mmdbFilePtr *geoip2.Reader
)

type Config struct {
	Doh string                  `yaml:"doh"`
	AdguardHome string           `yaml:"adguard-home"`
	Authorization string          `yaml:"authorization"`
	StartQueryTime string        `yaml:"start-query-time"`
	DomainFormat string           `yaml:"domain-format"`
	Codes       []string           `yaml:"codes"`

}
type Question struct {
	Name string
}
type Record struct {
	Question *Question
}
type Adlog struct {
	Data []*Record
	Oldest string
}

type node struct{
	end bool
	folw map[byte] *node
}

func init() {
	flag.StringVar(&homeDir, "d", "./", "set configuration directory")
	flag.Parse()
}

func myInit()  {
	config = Config{
		Doh: "223.5.5.5",
		AdguardHome: "",
		Authorization: "xx:xx",
		StartQueryTime: "2022-09-01T00:00:00+08:00",

	}
	configFile := filepath.Join(homeDir, configfile)
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Can't find config, create a initial config file")

		if bytes, err := yaml.Marshal(&config); err != nil {
			log.Printf(err.Error())
		} else {
			err = os.WriteFile(configFile, bytes, 0666)
			if err != nil {
				log.Printf(err.Error())
			}
		}
	} else {
		if bytes, err := os.ReadFile(configFile); err == nil {
			if err = yaml.Unmarshal(bytes, &config); err != nil {
				log.Printf(err.Error())
			}
		} else  {
			log.Printf(err.Error())
		}

	}
	resolver = doh.Resolver{
		Host:  config.Doh, // Change this with your favourite DoH-compliant resolver.
		Class: doh.IN,
	}

	domainFile = filepath.Join(homeDir, domainFile)
	mmdbFile = filepath.Join(homeDir, mmdbFile)
	var err error
	domainFilePtr, err = OpenFile(domainFile)
	if err != nil {
		log.Fatal(err)
	}
	rd := bufio.NewReader(domainFilePtr)

	for {
		line, err := rd.ReadString('\n')
		if err != nil || err == io.EOF {
			break
		}
		firstSlash := strings.Index(line, "/")
		if firstSlash == -1 {
			continue
		}
		firstSlash += 1
		secondSlash := strings.Index(line[firstSlash:], "/")
		if secondSlash == -1 {
			continue
		}

		domain := line[firstSlash: firstSlash + secondSlash]
		hasDomain(domain)
	}

	mmdbFilePtr, err = geoip2.Open(mmdbFile)
	if err != nil {
		log.Fatal(err)
	}
}

func lookup(domain string) (ip string, err error)  {
	a, _, err := resolver.LookupA(domain)
	if err != nil {
		return "", err
	}
	if len(a) == 0 {
		return "", errors.New("invalid lookup")
	}
	ip = a[0].IP4
	return ip, nil
}
func querylog(oldest, limit string) (adlog *Adlog, err error) {
	client := &http.Client{}
	url := config.AdguardHome + "/control/querylog?older_than=" + url.QueryEscape(oldest) + "&limit=" + limit
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	authorization := config.Authorization
	encoded := base64.StdEncoding.EncodeToString([]byte(authorization))
	req.Header.Add("Authorization", "Basic " + encoded)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	adlog = &Adlog{}
	if err = json.Unmarshal(b, &adlog); err != nil {
		return nil, err
	}
	return adlog, nil
}

func hasDomain(domain string) (has bool) {
	bytes := []byte(domain)
	var preNode *node = nil
	var ok bool = false
	has = true
	for _, b := range bytes {
		if preNode == nil {
			preNode, ok = Tree[b]
			if !ok {
				preNode = &node{
					end:  false,
					folw: make(map[byte] *node),
				}
				Tree[b] = preNode
				has = false
			}
		} else {
			preNode2, ok := preNode.folw[b]
			if !ok {
				preNode2 = &node{
					end:  false,
					folw: make(map[byte] *node),
				}
				preNode.folw[b]= preNode2
				has = false
			}
			preNode = preNode2
		}

	}
	if preNode != nil {
		if !preNode.end {
			preNode.end = true
			has = false
		}
	}
	return
}

func OpenFile(filename string) (*os.File, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return os.Create(filename)
	}
	return os.OpenFile(filename, os.O_APPEND|os.O_RDWR, os.ModePerm)
}

func do()  {
	ooldest := config.StartQueryTime
	startT, err := time.Parse(time.RFC3339, config.StartQueryTime)
	if err != nil {
		log.Printf("start query time err %s", err.Error())
		os.Exit(1)
	}
	startT = startT.Add(time.Minute)
	oldest := startT.Format(time.RFC3339)

	limit := "100"
	for {
		if startT.After(time.Now()) {
			time.Sleep(2 * time.Minute)
			domainFilePtr.Close()
			var err error
			domainFilePtr, err = OpenFile(domainFile)
			if err != nil {
				log.Fatal(err)
			}
		}
		if adlog, err := querylog(oldest, limit); err != nil {
			log.Printf(err.Error())
		} else {
			if adlog.Oldest > ooldest {
				oldest = adlog.Oldest
			} else {
				ooldest = startT.Format(time.RFC3339)
				log.Printf(ooldest)
				startT = startT.Add(time.Minute)
				oldest = startT.Format(time.RFC3339)
			}
			for _, e := range adlog.Data {
				domain := e.Question.Name
				//dnsServer.Prepare: preparing upstream settings: parsing upstream config: bad domain name "upload_data.qq.com": bad domain name label "upload_data": bad domain name label rune '_'
				underscore := strings.Index(domain, "_")
				if underscore != -1 {
					log.Printf(" there is a underscore in %s, skipping it", domain)
					continue
				}
				if !hasDomain(domain) {
					if ipstr, err := lookup(domain); err == nil {
						ip := net.ParseIP(ipstr)
						if country, err := mmdbFilePtr.Country(ip); err == nil {
							code := country.Country.IsoCode
							var contain = false
							for _, c := range config.Codes {
								if c == code {
									contain = true
									break
								}
							}
							if contain {
								str := fmt.Sprintf(config.DomainFormat, domain)
								log.Printf(str)
								if _, err := io.WriteString(domainFilePtr, str); err != nil {
									log.Fatal(err.Error())
								}
							}

						} else {
							log.Fatal(err)
						}
					}

				}
			}
			config.StartQueryTime = ooldest
		}
	}

}
func main() {

	myInit()
	go do()
	//has := hasDomain("g.alicdn.com")
	////has := hasDomain("m.aty.sohu.com")
	//log.Printf("%v", has)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	if domainFilePtr != nil {
		domainFilePtr.Close()
	}
	if mmdbFilePtr != nil {
		mmdbFilePtr.Close()
	}

	if bytes, err :=yaml.Marshal(config); err == nil {
		err = os.WriteFile(configfile, bytes, 0666)
		if err != nil {
			log.Fatal(err)
		}

	}

}