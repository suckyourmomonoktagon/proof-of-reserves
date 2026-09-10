package common

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

var PorCoinDataMap map[string]*CoinData

type CoinData struct {
	Coin           string
	Network        string
	SnapshotHeight string
	Address        string
	Balance        string
	Message        string
	Sign1          string
	Sign2          string
	Script         string
}

func DetectPorFormatOffset(header []string) int {
	for _, col := range header {
		if strings.EqualFold(strings.TrimSpace(col), "Type") {
			return 1
		}
	}
	return 0
}

func InitPorCsvDataMap(fileName string) (coinData map[string]*CoinData, err error) {
	fs, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("can not open the file, err is %+v", err)
		return
	}
	defer fs.Close()
	coinData = make(map[string]*CoinData)

	buf := bufio.NewReader(fs)
	off := 0
	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
		}

		if strings.Contains(string(line), "coin,") {
			off = DetectPorFormatOffset(ParseCSVLine(string(line)))
			continue
		}

		args := ParseCSVLine(string(line))
		if len(args) < 9+off {
			continue
		}
		// coin,[type,]network,snapshot height,address,balance,message,signature1,signature2,redeem_script
		d := &CoinData{
			Coin:           strings.ToUpper(cleanout(args[0])),
			Network:        strings.ToUpper(cleanout(args[1+off])),
			SnapshotHeight: cleanout(args[2+off]),
			Address:        cleanout(args[3+off]),
			Balance:        cleanout(args[4+off]),
			Message:        cleanout(args[5+off]),
			Sign1:          cleanout(args[6+off]),
			Sign2:          cleanout(args[7+off]),
			Script:         cleanout(args[8+off]),
		}
		if _, exist := coinData[fmt.Sprintf("%s:%s", d.Coin, d.Address)]; !exist {
			coinData[fmt.Sprintf("%s:%s", d.Coin, d.Address)] = d
		}
	}

	return coinData, nil
}

func cleanout(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
