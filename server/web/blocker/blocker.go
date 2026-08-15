package blocker

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"server/log"
	"server/settings"

	"github.com/gin-gonic/gin"
)

const (
	blacklistURL      = "https://raw.githubusercontent.com/waelisa/Best-blocklist/main/wael.list.p2p.zip"
	blacklistInterval = 24 * time.Hour
)

var (
	blackIpList   Ranger
	blackIpListMu sync.RWMutex
)

func Blocker() gin.HandlerFunc {
	emptyFN := func(c *gin.Context) {
		c.Next()
	}

	name := filepath.Join(settings.Path, "bip.txt")
	buf, _ := os.ReadFile(name)

	blackIpListMu.Lock()
	blackIpList = scanBuf(buf)
	blackIpListMu.Unlock()

	name = filepath.Join(settings.Path, "wip.txt")
	buf, _ = os.ReadFile(name)
	whiteIpList := scanBuf(buf)

	// Start the blacklist updater without blocking startup.
	go updateBlacklist()

	blackIpListMu.RLock()
	hasBlackList := blackIpList.NumRanges() > 0
	blackIpListMu.RUnlock()

	if !hasBlackList && whiteIpList.NumRanges() == 0 {
		return emptyFN
	}

	return func(c *gin.Context) {
		arr := strings.Split(c.Request.RemoteAddr, ":")
		if len(arr) > 0 {
			ip := net.ParseIP(arr[0])
			minifyIP(&ip)

			if whiteIpList.NumRanges() > 0 {
				if _, ok := whiteIpList.Lookup(ip); !ok {
					log.WebLogln("Block ip, not in white list", ip.String())
					c.String(http.StatusTeapot, "Banned")
					c.Abort()
					return
				}
			}

			blackIpListMu.RLock()
			currentBlackIpList := blackIpList
			blackIpListMu.RUnlock()

			if currentBlackIpList.NumRanges() > 0 {
				if r, ok := currentBlackIpList.Lookup(ip); ok {
					log.WebLogln("Block ip, in black list:", ip.String(), "in range", r.Description, ":", r.First, "-", r.Last)
					c.String(http.StatusTeapot, "Banned")
					c.Abort()
					return
				}
			}
		}
		c.Next()
	}
}

func scanBuf(buf []byte) Ranger {
	if len(buf) == 0 {
		return New(nil)
	}
	var ranges []Range
	scanner := bufio.NewScanner(strings.NewReader(string(buf)))
	for scanner.Scan() {
		r, ok, err := parseLine(scanner.Bytes())
		if err != nil {
			log.TLogln("Error scan ip list:", err)
			return New(nil)
		}
		if ok {
			ranges = append(ranges, r)
		}
	}
	err := scanner.Err()
	if err != nil {
		log.TLogln("Error scan ip list:", err)
	}
	if len(ranges) > 0 {
		return New(ranges)
	}
	return New(nil)
}

func parseLine(l []byte) (r Range, ok bool, err error) {
	l = bytes.TrimSpace(l)
	if len(l) == 0 || bytes.HasPrefix(l, []byte("#")) {
		return
	}
	colon := bytes.LastIndexAny(l, ":")
	hyphen := bytes.IndexByte(l[colon+1:], '-')
	hyphen += colon + 1
	if colon >= 0 {
		r.Description = string(l[:colon])
	}
	if hyphen-(colon+1) >= 0 {
		r.First = net.ParseIP(string(l[colon+1 : hyphen]))
		minifyIP(&r.First)
		r.Last = net.ParseIP(string(l[hyphen+1:]))
		minifyIP(&r.Last)
	} else {
		r.First = net.ParseIP(string(l[colon+1:]))
		minifyIP(&r.First)
		r.Last = r.First
	}
	if r.First == nil || r.Last == nil || len(r.First) != len(r.Last) {
		err = errors.New("bad IP range")
		return
	}
	ok = true
	return
}

// Downloads the blacklist when the local copy is missing or expired.
func updateBlacklist() {
	name := filepath.Join(settings.Path, "bip.txt")

	info, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			updateBlacklistOnce()
		} else {
			log.TLogln("Error checking blacklist:", err)
		}
	} else if time.Since(info.ModTime()) >= blacklistInterval {
		updateBlacklistOnce()
	}

	for {
		info, err := os.Stat(name)
		if err != nil {
			time.Sleep(blacklistInterval)
			updateBlacklistOnce()
			continue
		}
		remaining := blacklistInterval - time.Since(info.ModTime())
		if remaining < 0 {
			remaining = 0
		}
		timer := time.NewTimer(remaining)
		<-timer.C

		updateBlacklistOnce()
	}
}

// Downloads, extracts and validates the blacklist.
func updateBlacklistOnce() {
	data, err := downloadBlacklist()
	if err != nil {
		log.TLogln("Error downloading blacklist:", err)
		return
	}
	newBlackIpList := scanBuf(data)
	if newBlackIpList.NumRanges() == 0 {
		log.TLogln("Downloaded blacklist is empty or invalid")
		return
	}
	name := filepath.Join(settings.Path, "bip.txt")
	if err := os.WriteFile(name, data, 0644); err != nil {
		log.TLogln("Error saving blacklist:", err)
		return
	}

	blackIpListMu.Lock()
	blackIpList = newBlackIpList
	blackIpListMu.Unlock()

	log.TLogln("Blacklist updated:", newBlackIpList.NumRanges(), "ranges")
}

// Downloads and extracts the P2P list from the ZIP archive.
func downloadBlacklist() ([]byte, error) {
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}
	resp, err := client.Get(blacklistURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, file := range zipReader.File {
		if !strings.HasSuffix(strings.ToLower(file.Name), ".p2p") {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(reader)
		reader.Close()

		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, errors.New("P2P blacklist not found in archive")
}
