
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const version = "0.1.0"

const banner = `
   ______ _    _ ______ _____  ______      ______ 
  / ____/| |  | |  ____|  __ \|  ____|    / / __ \
 | |     | |  | | |__  | |__) | |__      / / |  | |
 | |     | |  | |  __| |  _  /|  __|    / /| |  | |
 | |____ | |__| | |____| | \ \| |____  / / | |__| |
  \_____| \____/|______|_|  \_\______|/_/   \____/ 

 CUERVO - descubrimiento técnico, inventario digital y OSINT web
`

type Finding struct {
	Target    string                 `json:"target"`
	Module    string                 `json:"module"`
	Type      string                 `json:"type"`
	Value     string                 `json:"value"`
	Tags      []string               `json:"tags,omitempty"`
	Timestamp string                 `json:"timestamp"`
	Evidence  map[string]any         `json:"evidence,omitempty"`
}

type MemoryStore struct {
	Version  string    `json:"version"`
	Updated  string    `json:"updated"`
	Seeds    []string  `json:"seeds,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type ExecContext struct {
	Target       string
	BaseURL      *url.URL
	HTTPClient   *http.Client
	Wordlists    []string
	JSON         bool
	Verbose      bool
	Timeout      time.Duration
	MemoryPath   string
	SaveMemory   bool
	Memory       *MemoryStore
	Findings     []Finding
	CustomHeader http.Header
}

type Module func(context.Context, *ExecContext) error

func main() {
	if len(os.Args) == 1 {
		printRootHelp()
		return
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		printRootHelp()
		return
	case "-v", "--version", "version":
		fmt.Println("CUERVO", version)
		return
	}

	moduleName := os.Args[1]
	target := ""
	if len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
		target = os.Args[2]
	}

	moduleFn, ok := modules()[moduleName]
	if !ok {
		fatalf("módulo desconocido: %s\n\n", moduleName)
		printRootHelp()
		os.Exit(1)
	}

	fs := flag.NewFlagSet(moduleName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	jsonOut := fs.Bool("json", false, "salida en JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout HTTP")
	wordlistsFlag := fs.String("wordlists", "base", "wordlists a combinar: base,extra,archivo.txt")
	memoryPath := fs.String("memory", defaultMemoryPath(), "ruta de memoria local")
	saveMemory := fs.Bool("save-memory", false, "guardar hallazgos y semillas")
	verbose := fs.Bool("v", false, "modo verbose")
	userAgent := fs.String("ua", "CUERVO/"+version, "User-Agent HTTP")
	headerList := fs.String("H", "", "headers extra en formato 'Key: Value;Key2: Value2'")

	var argsToParse []string
	if target == "" {
		argsToParse = os.Args[2:]
	} else {
		argsToParse = os.Args[3:]
	}

	if err := fs.Parse(argsToParse); err != nil {
		fatalf("error parseando flags: %v\n", err)
	}

	if target == "" {
		remaining := fs.Args()
		if len(remaining) > 0 {
			target = remaining[0]
		}
	}

	if target == "" {
		fatalf("debes indicar un target. Ejemplo: cuervo expose https://example.com\n")
	}

	baseURL, err := normalizeURL(target)
	if err != nil {
		fatalf("target inválido: %v\n", err)
	}

	mergedWordlists, err := mergeWordlists(strings.Split(*wordlistsFlag, ","))
	if err != nil {
		fatalf("error cargando wordlists: %v\n", err)
	}

	mem, err := loadMemory(*memoryPath)
	if err != nil {
		fatalf("error cargando memoria: %v\n", err)
	}

	headers := make(http.Header)
	headers.Set("User-Agent", *userAgent)
	if strings.TrimSpace(*headerList) != "" {
		for _, segment := range strings.Split(*headerList, ";") {
			parts := strings.SplitN(segment, ":", 2)
			if len(parts) != 2 {
				continue
			}
			headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	ctx := &ExecContext{
		Target:       baseURL.String(),
		BaseURL:      baseURL,
		HTTPClient:   &http.Client{Timeout: *timeout},
		Wordlists:    mergedWordlists,
		JSON:         *jsonOut,
		Verbose:      *verbose,
		Timeout:      *timeout,
		MemoryPath:   *memoryPath,
		SaveMemory:   *saveMemory,
		Memory:       mem,
		CustomHeader: headers,
	}

	if !ctx.JSON {
		fmt.Println(banner)
		fmt.Printf("[*] módulo: %s\n[*] target: %s\n[*] wordlists: %d entradas\n\n", moduleName, ctx.Target, len(ctx.Wordlists))
	}

	if err := moduleFn(context.Background(), ctx); err != nil {
		fatalf("error en módulo %s: %v\n", moduleName, err)
	}

	if ctx.SaveMemory {
		ctx.Memory.Findings = append(ctx.Memory.Findings, ctx.Findings...)
		ctx.Memory.Seeds = uniqueStrings(append(ctx.Memory.Seeds, deriveSeeds(ctx.Findings)...))
		ctx.Memory.Updated = time.Now().UTC().Format(time.RFC3339)
		if err := saveMemory(ctx.MemoryPath, ctx.Memory); err != nil {
			fatalf("no se pudo guardar memoria: %v\n", err)
		}
		if !ctx.JSON {
			fmt.Printf("\n[*] memoria actualizada: %s\n", ctx.MemoryPath)
		}
	}

	if err := emitFindings(ctx); err != nil {
		fatalf("error imprimiendo salida: %v\n", err)
	}
}

func modules() map[string]Module {
	return map[string]Module{
		"passive": runPassive,
		"map":     runMap,
		"expose":  runExpose,
		"js":      runJS,
		"fuzz":    runFuzz,
	}
}

func runPassive(_ context.Context, e *ExecContext) error {
	host := e.BaseURL.Hostname()

	addFinding(e, "passive", "target.host", host, []string{"host"}, nil)

	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		addFinding(e, "passive", "dns.a", ip.String(), []string{"dns", "ip"}, nil)
	}

	cname, _ := net.LookupCNAME(host)
	if cname != "" && cname != host+"." {
		addFinding(e, "passive", "dns.cname", strings.TrimSuffix(cname, "."), []string{"dns", "cname"}, nil)
	}

	resp, body, err := doGET(e, e.BaseURL.String())
	if err == nil {
		addFinding(e, "passive", "http.status", fmt.Sprintf("%d", resp.StatusCode), []string{"http"}, map[string]any{"url": e.BaseURL.String()})
		server := resp.Header.Get("Server")
		if server != "" {
			addFinding(e, "passive", "http.server", server, []string{"http", "header"}, nil)
		}
		powered := resp.Header.Get("X-Powered-By")
		if powered != "" {
			addFinding(e, "passive", "http.powered_by", powered, []string{"http", "header"}, nil)
		}
		title := extractTitle(body)
		if title != "" {
			addFinding(e, "passive", "html.title", title, []string{"html", "metadata"}, nil)
		}
	}

	return nil
}

func runMap(_ context.Context, e *ExecContext) error {
	if err := runPassive(context.Background(), e); err != nil {
		return err
	}

	resp, body, err := doGET(e, e.BaseURL.String())
	if err != nil {
		return err
	}
	addFinding(e, "map", "http.final_url", resp.Request.URL.String(), []string{"http", "map"}, nil)

	for _, path := range extractHTMLRefs(body) {
		ref := resolveURLString(e.BaseURL, path)
		addFinding(e, "map", "resource.reference", ref, []string{"resource", "reference"}, nil)
	}

	return nil
}

func runExpose(_ context.Context, e *ExecContext) error {
	for _, word := range prioritizedWords(e) {
		u := joinURLPath(e.BaseURL, word)
		resp, _, err := doGET(e, u)
		if err != nil {
			continue
		}
		if resp.StatusCode < 400 {
			addFinding(e, "expose", "public.path", u, []string{"exposed", "path"}, map[string]any{
				"status": resp.StatusCode,
			})
		}
	}
	return nil
}

func runJS(_ context.Context, e *ExecContext) error {
	resp, body, err := doGET(e, e.BaseURL.String())
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return errors.New("respuesta no útil del target base")
	}

	jsRefs := extractJSRefs(body)
	if len(jsRefs) == 0 {
		return nil
	}

	endpointRe := regexp.MustCompile(`(?i)(/[a-z0-9_\-./?=&]+|https?://[a-z0-9.\-_/?:=&%#]+)`)
	for _, ref := range jsRefs {
		jsURL := resolveURLString(e.BaseURL, ref)
		addFinding(e, "js", "js.file", jsURL, []string{"javascript", "asset"}, nil)

		resp, jsBody, err := doGET(e, jsURL)
		if err != nil || resp.StatusCode >= 400 {
			continue
		}

		matches := endpointRe.FindAllString(jsBody, -1)
		for _, m := range uniqueStrings(matches) {
			if len(m) < 4 {
				continue
			}
			addFinding(e, "js", "js.endpoint_candidate", m, []string{"javascript", "candidate"}, map[string]any{
				"source": jsURL,
			})
		}

		for _, host := range extractDomains(jsBody) {
			addFinding(e, "js", "js.domain_candidate", host, []string{"javascript", "domain"}, map[string]any{
				"source": jsURL,
			})
		}
	}

	return nil
}

func runFuzz(_ context.Context, e *ExecContext) error {
	client := *e.HTTPClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, word := range prioritizedWords(e) {
		u := joinURLPath(e.BaseURL, word)
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header = e.CustomHeader.Clone()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 204 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			addFinding(e, "fuzz", "route.response", u, []string{"fuzz", "route"}, map[string]any{
				"status":   resp.StatusCode,
				"location": resp.Header.Get("Location"),
			})
		}
	}
	return nil
}

func normalizeURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("debe incluir host válido")
	}
	return u, nil
}

func defaultMemoryPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cuervo-memory.json"
	}
	return filepath.Join(home, ".config", "cuervo", "memory.json")
}

func loadMemory(path string) (*MemoryStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &MemoryStore{
				Version: version,
				Updated: time.Now().UTC().Format(time.RFC3339),
			}, nil
		}
		return nil, err
	}
	var store MemoryStore
	if err := json.Unmarshal(b, &store); err != nil {
		return nil, err
	}
	if store.Version == "" {
		store.Version = version
	}
	return &store, nil
}

func saveMemory(path string, store *MemoryStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func mergeWordlists(sources []string) ([]string, error) {
	var merged []string
	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		switch src {
		case "base":
			merged = append(merged, embeddedBaseWordlist()...)
		case "extra":
			merged = append(merged, embeddedExtraWordlist()...)
		default:
			lines, err := readLines(src)
			if err != nil {
				return nil, fmt.Errorf("no se pudo leer %s: %w", src, err)
			}
			merged = append(merged, lines...)
		}
	}
	return uniqueStrings(cleanWords(merged)), nil
}

func embeddedBaseWordlist() []string {
	return []string{
		"robots.txt", ".git/config", ".env", "config.php", "backup.zip",
		"admin", "login", "api", "api/v1", "swagger", "openapi.json",
		"sitemap.xml", "crossdomain.xml", "server-status", "health", "metrics",
	}
}

func embeddedExtraWordlist() []string {
	return []string{
		"debug", "dashboard", "graphql", "actuator", "console",
		"assets", "static", "uploads", "tmp", "backup", "old", "dev", "test",
	}
}

func cleanWords(in []string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		item = strings.TrimPrefix(item, "/")
		if item == "" || strings.HasPrefix(item, "#") {
			continue
		}
		out = append(out, item)
	}
	return out
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func prioritizedWords(e *ExecContext) []string {
	words := append([]string{}, e.Wordlists...)
	words = append(words, e.Memory.Seeds...)
	return uniqueStrings(cleanWords(words))
}

func deriveSeeds(findings []Finding) []string {
	var seeds []string
	for _, f := range findings {
		switch f.Type {
		case "public.path", "resource.reference", "js.endpoint_candidate":
			if strings.HasPrefix(f.Value, "/") {
				seeds = append(seeds, strings.TrimPrefix(f.Value, "/"))
				continue
			}
			if u, err := url.Parse(f.Value); err == nil && u.Path != "" {
				seeds = append(seeds, strings.TrimPrefix(u.Path, "/"))
			}
		}
	}
	return cleanWords(seeds)
}

func doGET(e *ExecContext, rawURL string) (*http.Response, string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header = e.CustomHeader.Clone()

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return resp, "", err
	}
	return resp, string(bodyBytes), nil
}

func addFinding(e *ExecContext, module, typ, value string, tags []string, evidence map[string]any) {
	e.Findings = append(e.Findings, Finding{
		Target:    e.Target,
		Module:    module,
		Type:      typ,
		Value:     value,
		Tags:      uniqueStrings(tags),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Evidence:  evidence,
	})
}

func emitFindings(e *ExecContext) error {
	if e.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(e.Findings)
	}

	if len(e.Findings) == 0 {
		fmt.Println("[*] sin hallazgos")
		return nil
	}

	sort.SliceStable(e.Findings, func(i, j int) bool {
		if e.Findings[i].Module == e.Findings[j].Module {
			if e.Findings[i].Type == e.Findings[j].Type {
				return e.Findings[i].Value < e.Findings[j].Value
			}
			return e.Findings[i].Type < e.Findings[j].Type
		}
		return e.Findings[i].Module < e.Findings[j].Module
	})

	fmt.Println("[+] hallazgos")
	for _, f := range e.Findings {
		fmt.Printf(" - [%s] %s => %s\n", f.Type, f.Module, f.Value)
		if len(f.Tags) > 0 {
			fmt.Printf("   tags: %s\n", strings.Join(f.Tags, ", "))
		}
		if len(f.Evidence) > 0 {
			if b, err := json.Marshal(f.Evidence); err == nil {
				fmt.Printf("   evidence: %s\n", b)
			}
		}
	}
	return nil
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(stripTags(m[1]))
}

func stripTags(s string) string {
	re := regexp.MustCompile(`(?is)<[^>]+>`)
	return re.ReplaceAllString(s, "")
}

func extractHTMLRefs(body string) []string {
	re := regexp.MustCompile(`(?i)(?:href|src)=["']([^"'#]+)["']`)
	matches := re.FindAllStringSubmatch(body, -1)
	var refs []string
	for _, m := range matches {
		if len(m) > 1 {
			refs = append(refs, m[1])
		}
	}
	return uniqueStrings(refs)
}

func extractJSRefs(body string) []string {
	re := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	matches := re.FindAllStringSubmatch(body, -1)
	var refs []string
	for _, m := range matches {
		if len(m) > 1 {
			refs = append(refs, m[1])
		}
	}
	return uniqueStrings(refs)
}

func extractDomains(body string) []string {
	re := regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`)
	return uniqueStrings(re.FindAllString(strings.ToLower(body), -1))
}

func resolveURLString(base *url.URL, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(u).String()
}

func joinURLPath(base *url.URL, path string) string {
	ref := &url.URL{Path: "/" + strings.TrimPrefix(path, "/")}
	return base.ResolveReference(ref).String()
}

func printRootHelp() {
	fmt.Println(banner)
	fmt.Println("Uso:")
	fmt.Println("  cuervo <modulo> <target> [flags]")
	fmt.Println("")
	fmt.Println("Módulos:")
	fmt.Println("  passive   Recopilación pasiva (DNS, headers, metadata)")
	fmt.Println("  map       Correlación básica de recursos enlazados")
	fmt.Println("  expose    Detección de rutas/archivos públicos desde wordlists")
	fmt.Println("  js        Análisis simple de JavaScript público")
	fmt.Println("  fuzz      Exploración controlada de rutas")
	fmt.Println("")
	fmt.Println("Flags comunes:")
	fmt.Println("  --wordlists base,extra,custom.txt   Combina wordlists preservando orden")
	fmt.Println("  --json                              Salida JSON")
	fmt.Println("  --memory PATH                       Ruta de memoria local")
	fmt.Println("  --save-memory                       Guarda hallazgos/semillas")
	fmt.Println("  --timeout 10s                       Timeout HTTP")
	fmt.Println("  -v                                  Verbose")
	fmt.Println("")
	fmt.Println("Ejemplos:")
	fmt.Println("  cuervo expose https://example.com --wordlists base,extra")
	fmt.Println("  cuervo js https://example.com --json")
	fmt.Println("  cuervo fuzz https://example.com --wordlists base,custom.txt --save-memory")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}
