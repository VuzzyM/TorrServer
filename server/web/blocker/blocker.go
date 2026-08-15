package blocker

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	blacklistURL      = "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz"
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

	// Start the blacklist updater without blocking TorrServer startup.
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

// Downloads the blacklist only when the local copy is missing or expired.
func updateBlacklist() {
	name := filepath.Join(settings.Path, "bip.txt")

	info, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			updateBlacklistOnce()
		} else {
			log.TLogln("Error checking blacklist:", err)
		}
	} else {
		remaining := blacklistInterval - time.Since(info.ModTime())

		if remaining <= 0 {
			updateBlacklistOnce()
		} else {
			log.TLogln("Blacklist is up to date, next update in:", remaining)
		}
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

// Downloads and decompresses the blacklist archive.
func updateBlacklistOnce() {
	data, err := downloadBlacklist()
	if err != nil {
		log.TLogln("Error downloading blacklist:", err)
		return
	}

	// Validate the new list before replacing the current one.
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

	// Replace the active blacklist without restarting TorrServer.
	blackIpListMu.Lock()
	blackIpList = newBlackIpList
	blackIpListMu.Unlock()

	log.TLogln("Blacklist updated:", newBlackIpList.NumRanges(), "ranges")
}

// Downloads and decompresses the blacklist archive.
func downloadBlacklist() ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	resp, err := client.Get(blacklistURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	return io.ReadAll(gz)
}
