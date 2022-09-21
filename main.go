package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
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
	"regexp"
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
    domainFilePtr *os.File
	ranger cidranger.Ranger
    parseQueryLog bool
    parsePureTxt bool
    queryLog string
    domainRegex *regexp.Regexp

)

type Config struct {
	Doh string                  `yaml:"doh"`
	AdguardHome string           `yaml:"adguard-home"`
	Authorization string          `yaml:"authorization"`
	StartQueryTime string        `yaml:"start-query-time"`
	DomainRegex string         `yaml:"domain-regex"`

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
		DomainRegex: `[-a-z0-9]+\.(cat|goog|sohu|ac|academy|ac\.cn|accountant|accountants|actor|ad|adult|ae|aero|af|ag|agency|ah\.cn|ai|airforce|al|am|amsterdam|an|ao|apartments|app|aq|ar|archi|army|art|as|asia|associates|at|attorney|au|auction|auto|autos|aw|az|ba|baby|band|bar|barcelona|bargains|bayern|bb|bd|be|beauty|beer|berlin|best|bet|bf|bg|bh|bi|bid|bike|bingo|bio|biz|biz\.pl|bj|bj\.cn|black|blog|blue|bm|bn|bo|boats|boston|boutique|br|bs|bt|build|builders|business|buzz|bv|bw|by|bz|ca|cab|cafe|camera|camp|capital|car|cards|care|careers|cars|casa|cash|casino|catering|cc|cd|center|ceo|cf|cg|ch|charity|chat|cheap|church|ci|city|ck|cl|claims|cleaning|clinic|clothing|cloud|club|cm|cn|co|coach|codes|coffee|co\.in|co\.jp|co\.kr|college|com|com\.ag|com\.au|com\.br|com\.bz|com\.cn|com\.co|com\.es|com\.ky|community|com\.mx|company|com\.pe|com\.ph|com\.pl|computer|com\.tw|condos|construction|consulting|contact|contractors|co\.nz|cooking|cool|coop|co\.uk|country|coupons|courses|co\.za|cq\.cn|cr|credit|creditcard|cricket|cruises|cu|cv|cx|cy|cymru|cz|dance|date|dating|de|deals|degree|delivery|democrat|dental|dentist|design|dev|diamonds|digital|direct|directory|discount|dj|dk|dm|do|doctor|dog|domains|download|dz|earth|ec|edu|education|ee|eg|eh|email|energy|engineer|engineering|enterprises|equipment|er|es|estate|et|eu|events|exchange|expert|exposed|express|fail|faith|family|fan|fans|farm|fashion|fi|film|finance|financial|firm\.in|fish|fishing|fit|fitness|fj|fj\.cn|fk|flights|florist|fm|fo|football|forsale|foundation|fr|fun|fund|furniture|futbol|fyi|ga|gallery|games|garden|gay|gd|gd\.cn|ge|gen\.in|gf|gg|gh|gi|gifts|gives|gl|glass|global|gm|gmbh|gn|gold|golf|gov|gov\.cn|gp|gq|gr|graphics|gratis|green|gripe|group|gs|gs\.cn|gt|gu|guide|guru|gw|gx\.cn|gy|gz\.cn|ha\.cn|hair|haus|hb\.cn|health|healthcare|he\.cn|hi\.cn|hk|hk\.cn|hl\.cn|hm|hn|hn\.cn|hockey|holdings|holiday|homes|horse|hospital|host|house|hr|ht|hu|icu|id|idv|idv\.tw|ie|il|im|immo|immobilien|in|inc|ind\.in|industries|info|info\.pl|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|ist|istanbul|it|je|jetzt|jewelry|jl\.cn|jm|jo|jobs|jp|js\.cn|jx\.cn|kaufen|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|kp|kr|kw|ky|kz|la|land|law|lawyer|lb|lc|lease|legal|lgbt|li|life|lighting|limited|limo|link|live|lk|llc|ln\.cn|loan|loans|london|love|lr|ls|lt|ltd|ltda|lu|luxury|lv|ly|ma|maison|makeup|management|market|marketing|mba|mc|md|me|media|melbourne|memorial|men|menu|me\.uk|mg|mh|miami|mil|mk|ml|mm|mn|mo|mobi|mo\.cn|moda|moe|money|monster|mortgage|motorcycles|movie|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|ne\.kr|net|net\.ag|net\.au|net\.br|net\.bz|net\.cn|net\.co|net\.in|net\.ky|net\.nz|net\.pe|net\.ph|net\.pl|network|news|nf|ng|ni|ninja|nl|nm\.cn|no|nom\.co|nom\.es|nom\.pe|np|nr|nrw|nu|nx\.cn|nyc|nz|okinawa|om|one|onl|online|org|org\.ag|org\.au|org\.cn|org\.es|org\.in|org\.ky|org\.nz|org\.pe|org\.ph|org\.pl|org\.uk|pa|page|paris|partners|parts|party|pe|pet|pf|pg|ph|photography|photos|pictures|pink|pizza|pk|pl|place|plumbing|plus|pm|pn|poker|porn|pr|press|pro|productions|promo|properties|protection|ps|pt|pub|pw|py|qa|qh\.cn|quebec|quest|racing|re|realestate|recipes|red|rehab|reise|reisen|re\.kr|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rich|rip|ro|rocks|rodeo|ru|run|rw|ryukyu|sa|sale|salon|sarl|sb|sc|sc\.cn|school|schule|science|sd|sd\.cn|se|security|services|sex|sg|sh|sh\.cn|shiksha|shoes|shop|shopping|show|si|singles|site|sj|sk|ski|skin|sl|sm|sn|sn\.cn|so|soccer|social|software|solar|solutions|space|/span|sr|st|storage|store|stream|studio|study|style|supplies|supply|support|surf|surgery|sv|sx\.cn|sy|sydney|systems|sz|tax|taxi|tc|td|team|tech|technology|tel|tennis|tf|tg|th|theater|theatre|tienda|tips|tires|tj|tj\.cn|tk|tl|tm|tn|to|today|tokyo|tools|top|tours|town|toys|tp|tr|trade|training|travel|tt|tube|tv|tw|tw\.cn|tz|ua|ug|uk|um|university|uno|us|uy|uz|va|vacations|vc|ve|vegas|ventures|vet|vg|vi|viajes|video|villas|vin|vip|vision|vn|vodka|vote|voto|voyage|vu|wales|wang|watch|webcam|website|wedding|wf|wiki|win|wine|work|works|world|ws|wtf|xin|xj\.cn|xxx|xyz|xz\.cn|yachts|ye|yn\.cn|yoga|yokohama|yr|yt|yu|za|zj\.cn|zm|zone|zw|中国|中文网|企业|佛山|信息|公司|商城|商店|商标|在线|娱乐|广东|我爱你|手机|招聘|游戏|移动|网址|网络|集团|餐厅)$`,
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
		hasDomain(line)
	}

	domainRegex = regexp.MustCompile(config.DomainRegex)

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
	shortDomain := domainRegex.FindString(domain)
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