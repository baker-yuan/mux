package mux

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type routeRegexpOptions struct {
	strictSlash    bool // 指示路由是否严格区分末尾的斜杠。例如，如果strictSlash为true，那么/path/和/path可能被视为两个不同的路径。
	useEncodedPath bool // 指示路由是否使用编码后的路径。例如，如果useEncodedPath为true，那么路径中的特殊字符可能会被编码（如空格被编码为%20）。
}

// 正则匹配类型
type regexpType int

const (
	regexpTypePath   regexpType = 0 // 路径
	regexpTypeHost   regexpType = 1 // 主机类型
	regexpTypePrefix regexpType = 2 // 前缀
	regexpTypeQuery  regexpType = 3 // 查询参数
)

// newRouteRegexp parses a route template and returns a routeRegexp,
// used to match a host, a path or a query string.
//
// It will extract named variables, assemble a regexp to be matched, create
// a "reverse" template to build URLs and compile regexps to validate variable
// values used in URL building.
//
// Previously we accepted only Python-like identifiers for variable
// names ([a-zA-Z_][a-zA-Z0-9_]*), but currently the only restriction is that
// name and pattern can't be empty, and names can't contain a colon.
// 解析一个路由模板并返回一个routeRegexp，用于匹配主机、路径或查询字符串。
// @tpl 模板字符串
func newRouteRegexp(tpl string, typ regexpType, options routeRegexpOptions) (*routeRegexp, error) {
	// 这个函数的主要作用是解析路由模板，提取出变量名和模式，然后生成一个用于匹配主机、路径或查询字符串的正则表达式，以及一个用于生成URL的反向模板。

	// 函数首先检查模板字符串是否格式正确，如果不正确则返回错误。
	// Check if it is well-formed.
	idxs, errBraces := braceIndices(tpl)
	if errBraces != nil {
		return nil, errBraces
	}
	// Backup the original.
	template := tpl

	// Now let's parse it.
	defaultPattern := "[^/]+"

	// 然后，根据typ的类型设置默认的匹配模式。如果typ是查询类型，那么默认模式是.*；如果typ是主机类型，那么默认模式是[^.]+；否则默认模式是[^/]+。
	if typ == regexpTypeQuery {
		defaultPattern = ".*"
	} else if typ == regexpTypeHost {
		defaultPattern = "[^.]+"
	}

	// 接着，如果typ不是路径类型，那么将options.strictSlash设置为false。
	// Only match strict slash if not matching
	if typ != regexpTypePath {
		options.strictSlash = false
	}

	// 然后，如果options.strictSlash为true且模板字符串以斜杠结尾，那么将模板字符串的最后一个字符删除，并设置endSlash为true。
	// Set a flag for strictSlash.
	endSlash := false
	if options.strictSlash && strings.HasSuffix(tpl, "/") {
		tpl = tpl[:len(tpl)-1]
		endSlash = true
	}

	// 接下来，函数创建两个缓冲区pattern和reverse，并在pattern的开头添加一个^字符。
	varsN := make([]string, len(idxs)/2)
	varsR := make([]*regexp.Regexp, len(idxs)/2)
	pattern := bytes.NewBufferString("")
	pattern.WriteByte('^')
	reverse := bytes.NewBufferString("")

	// 然后，函数遍历模板字符串中的所有花括号，对每一对花括号，函数都会提取出变量名和模式，然后将它们添加到pattern和reverse中，并将变量名和编译后的模式添加到varsN和varsR中。
	var end int
	var err error
	for i := 0; i < len(idxs); i += 2 {
		// Set all values we are interested in.
		raw := tpl[end:idxs[i]]
		end = idxs[i+1]
		parts := strings.SplitN(tpl[idxs[i]+1:end-1], ":", 2)
		name := parts[0]
		patt := defaultPattern
		if len(parts) == 2 {
			patt = parts[1]
		}
		// Name or pattern can't be empty.
		if name == "" || patt == "" {
			return nil, fmt.Errorf("mux: missing name or pattern in %q",
				tpl[idxs[i]:end])
		}
		// Build the regexp pattern.
		fmt.Fprintf(pattern, "%s(?P<%s>%s)", regexp.QuoteMeta(raw), varGroupName(i/2), patt)

		// Build the reverse template.
		fmt.Fprintf(reverse, "%s%%s", raw)

		// Append variable name and compiled pattern.
		varsN[i/2] = name
		varsR[i/2], err = regexp.Compile(fmt.Sprintf("^%s$", patt))
		if err != nil {
			return nil, err
		}
	}

	// 接着，函数将模板字符串剩余的部分添加到pattern和reverse中。
	// Add the remaining.
	raw := tpl[end:]
	pattern.WriteString(regexp.QuoteMeta(raw))
	if options.strictSlash {
		pattern.WriteString("[/]?")
	}

	if typ == regexpTypeQuery {
		// Add the default pattern if the query value is empty
		if queryVal := strings.SplitN(template, "=", 2)[1]; queryVal == "" {
			pattern.WriteString(defaultPattern)
		}
	}
	if typ != regexpTypePrefix {
		pattern.WriteByte('$')
	}

	// 然后，如果typ是主机类型且pattern中不包含冒号，那么将wildcardHostPort设置为true。
	var wildcardHostPort bool
	if typ == regexpTypeHost {
		if !strings.Contains(pattern.String(), ":") {
			wildcardHostPort = true
		}
	}
	reverse.WriteString(raw)
	if endSlash {
		reverse.WriteByte('/')
	}

	// 接下来，函数编译pattern，如果编译过程中出现错误，就返回该错误。
	// Compile full regexp.
	reg, errCompile := regexp.Compile(pattern.String())
	if errCompile != nil {
		return nil, errCompile
	}

	// 然后，函数检查编译后的正则表达式中的子表达式数量是否等于花括号的数量的一半，如果不等于，那么抛出一个异常。
	// Check for capturing groups which used to work in older versions
	if reg.NumSubexp() != len(idxs)/2 {
		panic(fmt.Sprintf("route %s contains capture groups in its regexp. ", template) + "Only non-capturing groups are accepted: e.g. (?:pattern) instead of (pattern)")
	}

	// 最后，函数返回一个新的routeRegexp实例。
	// Done!
	return &routeRegexp{
		template:         template,
		regexpType:       typ,
		options:          options,
		regexp:           reg,
		reverse:          reverse.String(),
		varsN:            varsN,
		varsR:            varsR,
		wildcardHostPort: wildcardHostPort,
	}, nil
}

// routeRegexp stores a regexp to match a host or path and information to
// collect and validate route variables.
// 用于存储一个正则表达式以匹配主机或路径，以及收集和验证路由变量的信息。
type routeRegexp struct {
	// The unmodified template.
	// 这是一个字符串类型的字段，表示未修改的模板。
	template string

	// The type of match
	// 这是一个regexpType类型的字段，表示匹配的类型。
	regexpType regexpType

	// Options for matching
	// 这是一个routeRegexpOptions类型的字段，表示匹配的选项。
	options routeRegexpOptions

	// Expanded regexp.
	// 这是一个*regexp.Regexp类型的字段，表示扩展的正则表达式。
	regexp *regexp.Regexp

	// Reverse template.
	// 这是一个字符串类型的字段，表示反向模板。
	reverse string

	// Variable names.
	// 这是一个字符串类型的切片，表示变量名。
	varsN []string

	// Variable regexps (validators).
	// 这是一个*regexp.Regexp类型的切片，表示变量的正则表达式（验证器）。
	varsR []*regexp.Regexp

	// Wildcard host-port (no strict port match in hostname)
	// 这是一个布尔类型的字段。如果为true，表示在主机名中不进行严格的端口匹配。
	wildcardHostPort bool
}

// Match matches the regexp against the URL host or path.
func (r *routeRegexp) Match(req *http.Request, match *RouteMatch) bool {
	if r.regexpType == regexpTypeHost {
		host := getHost(req)
		if r.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		return r.regexp.MatchString(host)
	}

	if r.regexpType == regexpTypeQuery {
		return r.matchQueryString(req)
	}
	path := req.URL.Path
	if r.options.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	return r.regexp.MatchString(path)
}

// url builds a URL part using the given values.
func (r *routeRegexp) url(values map[string]string) (string, error) {
	urlValues := make([]interface{}, len(r.varsN), len(r.varsN))
	for k, v := range r.varsN {
		value, ok := values[v]
		if !ok {
			return "", fmt.Errorf("mux: missing route variable %q", v)
		}
		if r.regexpType == regexpTypeQuery {
			value = url.QueryEscape(value)
		}
		urlValues[k] = value
	}
	rv := fmt.Sprintf(r.reverse, urlValues...)
	if !r.regexp.MatchString(rv) {
		// The URL is checked against the full regexp, instead of checking
		// individual variables. This is faster but to provide a good error
		// message, we check individual regexps if the URL doesn't match.
		for k, v := range r.varsN {
			if !r.varsR[k].MatchString(values[v]) {
				return "", fmt.Errorf(
					"mux: variable %q doesn't match, expected %q", values[v],
					r.varsR[k].String())
			}
		}
	}
	return rv, nil
}

// getURLQuery returns a single query parameter from a request URL.
// For a URL with foo=bar&baz=ding, we return only the relevant key
// value pair for the routeRegexp.
func (r *routeRegexp) getURLQuery(req *http.Request) string {
	if r.regexpType != regexpTypeQuery {
		return ""
	}
	templateKey := strings.SplitN(r.template, "=", 2)[0]
	val, ok := findFirstQueryKey(req.URL.RawQuery, templateKey)
	if ok {
		return templateKey + "=" + val
	}
	return ""
}

// findFirstQueryKey returns the same result as (*url.URL).Query()[key][0].
// If key was not found, empty string and false is returned.
func findFirstQueryKey(rawQuery, key string) (value string, ok bool) {
	query := []byte(rawQuery)
	for len(query) > 0 {
		foundKey := query
		if i := bytes.IndexAny(foundKey, "&;"); i >= 0 {
			foundKey, query = foundKey[:i], foundKey[i+1:]
		} else {
			query = query[:0]
		}
		if len(foundKey) == 0 {
			continue
		}
		var value []byte
		if i := bytes.IndexByte(foundKey, '='); i >= 0 {
			foundKey, value = foundKey[:i], foundKey[i+1:]
		}
		if len(foundKey) < len(key) {
			// Cannot possibly be key.
			continue
		}
		keyString, err := url.QueryUnescape(string(foundKey))
		if err != nil {
			continue
		}
		if keyString != key {
			continue
		}
		valueString, err := url.QueryUnescape(string(value))
		if err != nil {
			continue
		}
		return valueString, true
	}
	return "", false
}

func (r *routeRegexp) matchQueryString(req *http.Request) bool {
	return r.regexp.MatchString(r.getURLQuery(req))
}

// braceIndices returns the first level curly brace indices from a string.
// It returns an error in case of unbalanced braces.
func braceIndices(s string) ([]int, error) {
	var level, idx int
	var idxs []int
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			if level++; level == 1 {
				idx = i
			}
		case '}':
			if level--; level == 0 {
				idxs = append(idxs, idx, i+1)
			} else if level < 0 {
				return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
	}
	return idxs, nil
}

// varGroupName builds a capturing group name for the indexed variable.
func varGroupName(idx int) string {
	return "v" + strconv.Itoa(idx)
}

// ----------------------------------------------------------------------------
// routeRegexpGroup
// ----------------------------------------------------------------------------

// routeRegexpGroup groups the route matchers that carry variables.
// 用于将携带变量的路由匹配器分组。
type routeRegexpGroup struct {
	host    *routeRegexp   // 这是一个*routeRegexp类型的字段，用于匹配主机。
	path    *routeRegexp   // 这是一个*routeRegexp类型的字段，用于匹配路径。
	queries []*routeRegexp // 这是一个*routeRegexp类型的切片，用于匹配查询参数。
}

// setMatch extracts the variables from the URL once a route matches.
func (v routeRegexpGroup) setMatch(req *http.Request, m *RouteMatch, r *Route) {
	// Store host variables.
	if v.host != nil {
		host := getHost(req)
		if v.host.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		matches := v.host.regexp.FindStringSubmatchIndex(host)
		if len(matches) > 0 {
			extractVars(host, matches, v.host.varsN, m.Vars)
		}
	}
	path := req.URL.Path
	if r.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	// Store path variables.
	if v.path != nil {
		matches := v.path.regexp.FindStringSubmatchIndex(path)
		if len(matches) > 0 {
			extractVars(path, matches, v.path.varsN, m.Vars)
			// Check if we should redirect.
			if v.path.options.strictSlash {
				p1 := strings.HasSuffix(path, "/")
				p2 := strings.HasSuffix(v.path.template, "/")
				if p1 != p2 {
					u, _ := url.Parse(req.URL.String())
					if p1 {
						u.Path = u.Path[:len(u.Path)-1]
					} else {
						u.Path += "/"
					}
					m.Handler = http.RedirectHandler(u.String(), http.StatusMovedPermanently)
				}
			}
		}
	}
	// Store query string variables.
	for _, q := range v.queries {
		queryURL := q.getURLQuery(req)
		matches := q.regexp.FindStringSubmatchIndex(queryURL)
		if len(matches) > 0 {
			extractVars(queryURL, matches, q.varsN, m.Vars)
		}
	}
}

// getHost tries its best to return the request host.
// According to section 14.23 of RFC 2616 the Host header
// can include the port number if the default value of 80 is not used.
func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.Host
	}
	return r.Host
}

func extractVars(input string, matches []int, names []string, output map[string]string) {
	for i, name := range names {
		output[name] = input[matches[2*i+2]:matches[2*i+3]]
	}
}
