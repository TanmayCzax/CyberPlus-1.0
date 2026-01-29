package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ===============================
// WEB SECURITY INTELLIGENCE
// ===============================

func WebFingerprint(domain string) {
	resp, err := http.Get("https://" + domain)
	if err != nil {
		fmt.Println("Website unreachable")
		return
	}
	defer resp.Body.Close()

	fmt.Println("Server:", resp.Header.Get("Server"))
	fmt.Println("Powered-By:", resp.Header.Get("X-Powered-By"))

	if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		fmt.Println("CDN: Cloudflare detected")
	}
}

func HTTPSecurityAudit(domain string) {
	resp, err := http.Get("https://" + domain)
	if err != nil {
		fmt.Println("HTTPS not enabled")
		return
	}
	defer resp.Body.Close()

	check := func(h string) {
		if resp.Header.Get(h) == "" {
			fmt.Println("Missing:", h)
		}
	}

	check("Strict-Transport-Security")
	check("Content-Security-Policy")
	check("X-Frame-Options")
	check("X-Content-Type-Options")
}

// ===============================
// NETWORK INTELLIGENCE
// ===============================

func PortProbe(host string) {
	ports := []string{"21", "22", "25", "53", "80", "443", "3306"}

	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", host+":"+p, 2*time.Second)
		if err == nil {
			fmt.Println("Open port:", p)
			conn.Close()
		}
	}
}

func DNSIntel(domain string) {
	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		fmt.Println("IP:", ip)
	}

	mx, _ := net.LookupMX(domain)
	for _, m := range mx {
		fmt.Println("MX:", m.Host)
	}
}

// ===============================
// PASSWORD LEAK CHECK (SAFE)
// ===============================

func PasswordLeakCheck(password string) {
	hash := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := full[:5]

	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		fmt.Println("Leak check failed")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), full[5:]) {
		fmt.Println(" Password found in data breaches")
	} else {
		fmt.Println("Password not found in known breaches")
	}
}

// ===============================
// FILE ANALYSIS
// ===============================

func FileEntropy(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("File error")
		return
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	size := float64(len(data))

	for _, c := range freq {
		p := float64(c) / size
		entropy -= p * math.Log2(p)
	}

	fmt.Printf("File entropy: %.2f\n", entropy)
	if entropy > 7.2 {
		fmt.Println(" High entropy (packed/encrypted)")
	}
}

// ===============================
// ATTACK SIMULATION
// ===============================

func BruteForceSimulation(user string, attempts int) {
	speed := 500 // attempts per second
	seconds := attempts / speed
	fmt.Println("User:", user)
	fmt.Println("Attempts:", attempts)
	fmt.Println("Estimated crack time:", seconds, "seconds")
}
