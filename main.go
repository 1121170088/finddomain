package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/1121170088/find-domain/search"
	"github.com/babolivier/go-doh-client"
	cidranger "github.com/yl2chen/cidranger"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"
	"github.com/1121170088/find-domain"
)

var (
	configfile = "config.yaml"
	homeDir string
	resolver doh.Resolver
	config Config
    Tree map[byte] *node = make(map[byte] *node)
    domainFile = "list.txt"
    domainFilePtr *os.File
	ranger cidranger.Ranger
    parseQueryLog bool
    parsePureTxt bool
    queryLog string

)

type Config struct {
	Doh string                  `yaml:"doh"`
	AdguardHome string           `yaml:"adguard-home"`
	Authorization string          `yaml:"authorization"`
	StartQueryTime string        `yaml:"start-query-time"`
	DomainSuffixFile string       `yaml:"domain-suffix-file"`

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
	flag.StringVar(&domainFile, "o", "list.txt", "set output file name under -d")
	flag.BoolVar(&parseQueryLog, "adl", false, "parse anduard home log file mode, default false")
	flag.BoolVar(&parsePureTxt, "pt", false, "parse pure txt, default false")
	flag.StringVar(&queryLog, "f", "", "parse file")
	flag.Parse()
}

func myInit()  {
	config = Config{
		Doh: "dns-unfiltered.adguard.com",
		AdguardHome: "",
		Authorization: "xx:xx",
		StartQueryTime: "2022-09-01T00:00:00+08:00",
		DomainSuffixFile: "",
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
		os.Exit(1)
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
		line = strings.Trim(line, "\n")
		line = strings.Trim(line, "\r")
		line = strings.Trim(line, " ")
		hasDomain(line)
	}

	search.Init(config.DomainSuffixFile)

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

func reverse(s interface{}) {
	n := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}
func hasDomain(domain string) (has bool) {
	bytes := []byte(domain)
	reverse(bytes)
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
				handDomain(domain)
			}
			config.StartQueryTime = ooldest
		}
	}

}
func handDomain(domain string)  {
	shortDomain := searchDomain(domain)
	if shortDomain == "" {
		log.Printf(" %s is not a domain   %s", shortDomain, domain)
		return
	}

	if !hasDomain(shortDomain) {
		if _, err := io.WriteString(domainFilePtr, shortDomain +"\n"); err != nil {
			log.Fatal(err.Error())
		}
	} else  {
		log.Printf("%s has cached", domain)
	}
}
func isDomain(domain string) bool  {
	match1, _ := regexp.Match(`^[A-Za-z0-9-.]{1,63}$`, []byte(domain))
	match2, _ := regexp.Match(`[A-Za-z0-9-.]{1,63}\.[A-Za-z0-9-.]{1,63}`, []byte(domain))
	return  match1 && match2 && []byte(domain)[0] != '-'

}

func parseLog()  {
	var err error
	f, err := OpenFile(queryLog)
	if err != nil {
		log.Fatal(err)
	}
	rd := bufio.NewReader(f)

	for {
		line, err := rd.ReadString('\n')
		if err != nil || err == io.EOF {
			break
		}
		var dm = struct {
			QH string
		}{}
		err = json.Unmarshal([]byte(line), &dm)
		if err != nil {
			log.Printf(err.Error())
			continue
		}
		domain := dm.QH
		handDomain(domain)
	}
}
func parseTxt()  {
	var err error
	f, err := OpenFile(queryLog)
	if err != nil {
		log.Fatal(err)
	}
	rd := bufio.NewReader(f)

	for {
		line, err := rd.ReadString('\n')
		if err != nil || err == io.EOF {
			break
		}
		line = strings.Trim(line, "\n")
		line = strings.Trim(line, "\r")
		line = strings.Trim(line, " ")
		domain := line
		handDomain(domain)
	}
}

func searchDomain(domain string) string  {
	shortDomain := search.Search(domain)
	if isDomain(shortDomain) {
		return shortDomain
	}
	return ""
}
func main() {

	myInit()

	if parseQueryLog {
		parseLog()
	} else if parsePureTxt {
		parseTxt()
	} else {
		go do()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
	}
	if domainFilePtr != nil {
		domainFilePtr.Close()
	}

	if bytes, err :=yaml.Marshal(config); err == nil {
		err = os.WriteFile(configfile, bytes, 0666)
		if err != nil {
			log.Fatal(err)
		}
	}

}