package sessions

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Most code mirrored from go 1.13.7

// isCookieDomainName reports whether s is a valid domain name or a valid
// domain name with a leading dot '.'.  It is almost a direct copy of
// package net's isDomainName.
func isCookieDomainName(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	if s[0] == '.' {
		// A cookie a domain attribute may start with a leading dot.
		s = s[1:]
	}
	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
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

	return ok
}

// SameSite allows a server to define a cookie attribute making it impossible for
// the browser to send this cookie along with cross-site requests. The main
// goal is to mitigate the risk of cross-origin information leakage, and provide
// some protection against cross-site request forgery attacks.
//
// See https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00 for details.
type SameSite int

const (
	SameSiteDefaultMode SameSite = iota + 1
	SameSiteLaxMode
	SameSiteStrictMode
	SameSiteNoneMode
)

// https://tools.ietf.org/html/rfc6265#section-4.1.1
// cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//           ; US-ASCII characters excluding CTLs,
//           ; whitespace DQUOTE, comma, semicolon,
//           ; and backslash
// We loosen this as spaces and commas are common in cookie values
// but we produce a quoted cookie-value in when value starts or ends
// with a comma or space.
// See https://golang.org/issue/7243 for the discussion.
func sanitizeCookieValue(v string) string {
	v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
	if len(v) == 0 {
		return v
	}
	if strings.IndexByte(v, ' ') >= 0 || strings.IndexByte(v, ',') >= 0 {
		return `"` + v + `"`
	}
	return v
}

func sanitizeOrWarn(fieldName string, valid func(byte) bool, v string) string {
	ok := true
	for i := 0; i < len(v); i++ {
		if valid(v[i]) {
			continue
		}
		log.Printf("net/http: invalid byte %q in %s; dropping invalid bytes", v[i], fieldName)
		ok = false
		break
	}
	if ok {
		return v
	}
	buf := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if b := v[i]; valid(b) {
			buf = append(buf, b)
		}
	}
	return string(buf)
}

// serializeCookie returns the serialization of the cookie for use in a Cookie
// header (if only Name and Value are set) or a Set-Cookie response
// header (if other fields are set).
// If c is nil or c.Name is invalid, the empty string is returned.
//
// Mirrored from http.Cookie.String() in go 1.13.7 and adapted
// to work with local SameSite.
func serializeCookie(cookie *http.Cookie) string {
	if cookie == nil || !isCookieNameValid(cookie.Name) {
		return ""
	}
	// extraCookieLength derived from typical length of cookie attributes
	// see RFC 6265 Sec 4.1.
	const extraCookieLength = 110
	var b strings.Builder
	b.Grow(len(cookie.Name) + len(cookie.Value) + len(cookie.Domain) + len(cookie.Path) + extraCookieLength)
	b.WriteString(cookie.Name)
	b.WriteRune('=')
	b.WriteString(sanitizeCookieValue(cookie.Value))

	if len(cookie.Path) > 0 {
		b.WriteString("; Path=")
		b.WriteString(sanitizeCookiePath(cookie.Path))
	}
	if len(cookie.Domain) > 0 {
		if validCookieDomain(cookie.Domain) {
			// A cookie.Domain containing illegal characters is not
			// sanitized but simply dropped which turns the cookie
			// into a host-only cookie. A leading dot is okay
			// but won't be sent.
			d := cookie.Domain
			if d[0] == '.' {
				d = d[1:]
			}
			b.WriteString("; Domain=")
			b.WriteString(d)
		} else {
			log.Printf("net/http: invalid Cookie.Domain %q; dropping domain attribute", cookie.Domain)
		}
	}
	var buf [len(http.TimeFormat)]byte
	if validCookieExpires(cookie.Expires) {
		b.WriteString("; Expires=")
		b.Write(cookie.Expires.UTC().AppendFormat(buf[:0], http.TimeFormat))
	}
	if cookie.MaxAge > 0 {
		b.WriteString("; Max-Age=")
		b.Write(strconv.AppendInt(buf[:0], int64(cookie.MaxAge), 10))
	} else if cookie.MaxAge < 0 {
		b.WriteString("; Max-Age=0")
	}
	if cookie.HttpOnly {
		b.WriteString("; HttpOnly")
	}
	if cookie.Secure {
		b.WriteString("; Secure")
	}
	switch SameSite(cookie.SameSite) {
	case SameSiteDefaultMode:
		b.WriteString("; SameSite")
	case SameSiteNoneMode:
		b.WriteString("; SameSite=None")
	case SameSiteLaxMode:
		b.WriteString("; SameSite=Lax")
	case SameSiteStrictMode:
		b.WriteString("; SameSite=Strict")
	}
	return b.String()
}

// setCookie adds a Set-Cookie header to the provided ResponseWriter's headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
//
// Mirrored from go 1.13.7 and adapted to use local
// func serializeCookie() instead of http.Cookie.String().
func setCookie(w http.ResponseWriter, cookie *http.Cookie) {
	if v := serializeCookie(cookie); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}

// validCookieDomain reports whether v is a valid cookie domain-value.
func validCookieDomain(v string) bool {
	if isCookieDomainName(v) {
		return true
	}
	if net.ParseIP(v) != nil && !strings.Contains(v, ":") {
		return true
	}
	return false
}

// validCookieExpires reports whether v is a valid cookie expires-value.
func validCookieExpires(t time.Time) bool {
	// IETF RFC 6265 Section 5.1.1.5, the year must not be less than 1601
	return t.Year() >= 1601
}

// path-av           = "Path=" path-value
// path-value        = <any CHAR except CTLs or ";">
func sanitizeCookiePath(v string) string {
	return sanitizeOrWarn("Cookie.Path", validCookiePathByte, v)
}

func validCookiePathByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != ';'
}

func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}
