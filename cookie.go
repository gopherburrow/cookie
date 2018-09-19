// Copyright 2009 to 2016 The Go Authors. Copyright 2018 The Gopher Burrow Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookie

import (
	"net"
	"net/http"
	"path"
	"strings"
)

//Copied from golang_org/x/net/httplex
var isTokenTable = [127]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'0':  true,
	'1':  true,
	'2':  true,
	'3':  true,
	'4':  true,
	'5':  true,
	'6':  true,
	'7':  true,
	'8':  true,
	'9':  true,
	'A':  true,
	'B':  true,
	'C':  true,
	'D':  true,
	'E':  true,
	'F':  true,
	'G':  true,
	'H':  true,
	'I':  true,
	'J':  true,
	'K':  true,
	'L':  true,
	'M':  true,
	'N':  true,
	'O':  true,
	'P':  true,
	'Q':  true,
	'R':  true,
	'S':  true,
	'T':  true,
	'U':  true,
	'W':  true,
	'V':  true,
	'X':  true,
	'Y':  true,
	'Z':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'a':  true,
	'b':  true,
	'c':  true,
	'd':  true,
	'e':  true,
	'f':  true,
	'g':  true,
	'h':  true,
	'i':  true,
	'j':  true,
	'k':  true,
	'l':  true,
	'm':  true,
	'n':  true,
	'o':  true,
	'p':  true,
	'q':  true,
	'r':  true,
	's':  true,
	't':  true,
	'u':  true,
	'v':  true,
	'w':  true,
	'x':  true,
	'y':  true,
	'z':  true,
	'|':  true,
	'~':  true,
}

//Derived from net/http isCookieNameValid
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	return strings.IndexFunc(name, isNotToken) < 0
}

//Copied from net/http
// validCookieDomain returns whether v is a valid cookie domain-value.
func ValidDomain(domain string) bool {
	if isCookieDomainName(domain) {
		return true
	}
	if net.ParseIP(domain) != nil && !strings.Contains(domain, ":") {
		return true
	}
	return false
}

//Copied from net/http
var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

//Derived from net/http
func ValidPath(path string) bool {
	for i := 0; i < len(path); i++ {
		if b := path[i]; !(0x20 <= b && b < 0x7f && b != ';') {
			return false
		}
	}
	return true
}

//DeepDelete send various Cookies (Request Host to just above root domain and Request Path to /) with MaxAge 0 in response,
//that commands the browser to delete all the possible conflicting cookies.
func DeepDelete(cookieName string, w http.ResponseWriter, r *http.Request) {
	//Extract all possible domain combination that can cause conflict.
	domains := []string{""}
	tempDomain := "." + r.Host
	for {
		domains = append(domains, tempDomain)
		parts := strings.Split(tempDomain, ".")[2:]
		if len(parts) < 2 {
			break
		}
		tempDomain = "." + strings.Join(parts, ".")
	}

	//Extract all possible path combination that can cause conflict.
	paths := []string{"", "/"}
	tempPath := r.URL.Path
	for {
		if tempPath == "" || tempPath == "." || tempPath == "/" {
			break
		}
		paths = append(paths, tempPath)
		tempPath = path.Dir(tempPath)
	}

	//Unfortunatelly the browser does not send the combination of domain and path that cause the conflict,
	//So every single combination of domain and path must be sent.
	for _, domain := range domains {
		for _, path := range paths {
			//A cookie with MaxAge=-1 (MaxAge 0 is sent in HTTP) is a command to browser to delete the cookie.
			cookie := &http.Cookie{
				Name:     cookieName,
				MaxAge:   -1,
				Secure:   true,
				HttpOnly: true,
				Domain:   domain,
				Path:     path,
			}

			//Send the cookie in response.
			http.SetCookie(w, cookie)
		}
	}
}

//Derived from net/http
// isCookieDomainName returns whether s is a valid domain with a leading dot '.' and has at least 2 parts (because browsers do not save root domains).
//It is almost a direct copy of package net/http's isCookieDomainName, but it requires the leading dot and 2 domain parts.
func isCookieDomainName(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	// A cookie domain attribute must start with a leading dot.
	if s[0] != '.' {
		return false
	}
	last := byte(s[0]) // = '.'
	ok := false        // Ok once we've seen a letter.
	partlen := 0
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			// No '_' allowed here (in contrast to package net).
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	if !ok {
		return false
	}

	//With leading dot there at least two domain parts.
	if strings.Count(s, ".") < 2 {
		return false
	}

	return true
}

//Derived from net/http isTokenRune
func isNotToken(r rune) bool {
	i := int(r)
	return i >= len(isTokenTable) || !isTokenTable[i]
}
