// SPDX-License-Identifier: BUSL-1.1

// Package openapi renders an OpenAPI 3 document from a [route.Registrar]'s
// policies, so a product's published API description cannot drift from the
// routes its daemon serves.
//
// The registry supplies every path, its methods and its policy — auth, CSRF,
// scope, rate limiting and the body cap — which is exactly the part a
// hand-written spec gets wrong. Prose, path parameter names and bodies come
// from a hand-written source document:
//
//	preamble:      # copied to the top level: openapi, info, servers, tags, components…
//	operations:
//	  "GET /api/v1/sessions/":          # "<METHOD> <registry path>"
//	    pathTemplate: /api/v1/sessions/{id}
//	    summary: …                      # everything else merges onto the operation
//
// The preamble's components must define the security schemes the generated
// operations name: [BearerAuth] and, for CSRF-protected routes, [CSRFToken].
// The emitter lives in its own package so a product that serves routes without
// publishing a document does not link a YAML encoder.
package openapi

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver/route"
)

// Security scheme names the generated operations reference.
const (
	BearerAuth = "BearerAuth"
	CSRFToken  = "CsrfToken"
)

// Options carries what only the product knows.
type Options struct {
	// Header is written verbatim before the document: the "generated, do not
	// edit" comment naming the product's generator. Each line needs its "#".
	Header string

	// ErrorSchema is the product's error envelope as a schema object. It is
	// published as components.schemas.Error, which every generated error
	// response references. Reflect it from the Go type in the product, so the
	// document cannot describe fields the daemon never sends.
	ErrorSchema map[string]any
}

// pathItem is one OpenAPI path object: lower-cased method names mapping to
// operations, plus the shared "parameters" list. Both stay map-shaped because
// that is what yaml.Marshal emits in sorted, diff-stable order.
type (
	operation map[string]any
	pathItem  map[string]any
)

// sourceDoc is the hand-written half of the document.
type sourceDoc struct {
	// Preamble is copied verbatim to the top level. `paths` is generated and
	// is rejected here.
	Preamble map[string]any `yaml:"preamble"`
	// Operations enriches a generated operation, keyed "<METHOD> <path>" with
	// the registry's own path (a prefix route keeps its trailing "/").
	Operations map[string]operationSource `yaml:"operations"`
}

// operationSource is one enrichment entry. Everything except pathTemplate is
// merged onto the generated operation object.
type operationSource struct {
	// PathTemplate renames a prefix route to its documented shape, e.g.
	// /api/v1/sessions/ -> /api/v1/sessions/{id}. Every method on one path
	// must agree, and the template's parameters are declared for it.
	PathTemplate string         `yaml:"pathTemplate"`
	Rest         map[string]any `yaml:",inline"`
}

// Generate renders the document from the source and the registry's policies.
func Generate(source []byte, routes []route.Policy, opts Options) ([]byte, error) {
	if opts.ErrorSchema == nil {
		return nil, errors.New("openapi: Options.ErrorSchema is required")
	}
	var src sourceDoc
	dec := yaml.NewDecoder(strings.NewReader(string(source)))
	dec.KnownFields(true)
	if err := dec.Decode(&src); err != nil {
		return nil, fmt.Errorf("parsing source: %w", err)
	}
	if _, ok := src.Preamble["paths"]; ok {
		return nil, errors.New("source preamble must not define `paths`: it is generated from the registry")
	}

	paths, err := buildPaths(routes, src.Operations)
	if err != nil {
		return nil, err
	}

	doc := map[string]any{}
	maps.Copy(doc, src.Preamble)
	doc["paths"] = paths

	components, _ := doc["components"].(map[string]any)
	if components == nil {
		components = map[string]any{}
		doc["components"] = components
	}
	schemas, _ := components["schemas"].(map[string]any)
	if schemas == nil {
		schemas = map[string]any{}
		components["schemas"] = schemas
	}
	schemas["Error"] = opts.ErrorSchema

	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append([]byte(opts.Header), body...), nil
}

func buildPaths(routes []route.Policy, ops map[string]operationSource) (map[string]any, error) {
	documented := make([]route.Policy, 0, len(routes))
	for _, rt := range routes {
		if !rt.Hidden {
			documented = append(documented, rt)
		}
	}

	templates, err := resolveTemplates(documented, ops)
	if err != nil {
		return nil, err
	}

	used := map[string]bool{}
	items := map[string]pathItem{}
	for _, rt := range documented {
		docPath := templates[rt.Path]
		if docPath == "" {
			docPath = defaultTemplate(rt.Path)
		}
		item, ok := items[docPath]
		if !ok {
			item = pathItem{}
			items[docPath] = item
		}
		if params := pathParameters(docPath); len(params) > 0 {
			item["parameters"] = params
		}
		for _, m := range methodsOf(rt) {
			key := m + " " + rt.Path
			used[key] = true
			// Two registry routes resolving to one documented method would
			// silently drop an operation, which is worse than a wrong one.
			if _, clash := item[strings.ToLower(m)]; clash {
				return nil, fmt.Errorf("%s %s is claimed by more than one registered route (last: %s)",
					m, docPath, rt.Path)
			}
			item[strings.ToLower(m)] = merge(newOperation(rt, m, docPath), ops[key].Rest)
		}
	}

	if idErr := checkOperationIDs(items); idErr != nil {
		return nil, idErr
	}
	if staleErr := checkStale(ops, used); staleErr != nil {
		return nil, staleErr
	}

	paths := make(map[string]any, len(items))
	for docPath, item := range items {
		paths[docPath] = map[string]any(item)
	}
	return paths, nil
}

// merge lays the source enrichment over a generated operation. `responses` is
// merged a level deeper: the policy-derived 401/403/405/413/429 set is what
// the composed middleware actually returns, so a source entry adding a 200
// documents its body without discarding them. A source entry for a status the
// generator also produced wins, since only the source knows the body.
func merge(op operation, src map[string]any) operation {
	for k, v := range src {
		if k != "responses" {
			op[k] = v
			continue
		}
		srcResponses, isMap := v.(map[string]any)
		generated, hasGenerated := op["responses"].(map[string]any)
		if !isMap || !hasGenerated {
			op[k] = v
			continue
		}
		maps.Copy(generated, srcResponses)
	}
	return op
}

// resolveTemplates maps each registry path to the documented shape the source
// gives it. Every method on one path must name the same one, or the document
// would claim two shapes for one route.
func resolveTemplates(routes []route.Policy, ops map[string]operationSource) (map[string]string, error) {
	templates := map[string]string{}
	for _, rt := range routes {
		for _, m := range methodsOf(rt) {
			src, ok := ops[m+" "+rt.Path]
			if !ok || src.PathTemplate == "" {
				continue
			}
			if prev, seen := templates[rt.Path]; seen && prev != src.PathTemplate {
				return nil, fmt.Errorf("%s: pathTemplate disagrees between methods (%q vs %q)",
					rt.Path, prev, src.PathTemplate)
			}
			templates[rt.Path] = src.PathTemplate
		}
	}
	return templates, nil
}

// checkOperationIDs rejects a duplicate id: it is invalid OpenAPI and
// generates colliding client methods.
func checkOperationIDs(items map[string]pathItem) error {
	seen := map[string]string{}
	for docPath, item := range items {
		for method, value := range item {
			op, ok := value.(operation)
			if !ok {
				continue // "parameters"
			}
			id, _ := op["operationId"].(string)
			if prev, dup := seen[id]; dup {
				return fmt.Errorf("duplicate operationId %q: %s and %s %s", id, prev, method, docPath)
			}
			seen[id] = method + " " + docPath
		}
	}
	return nil
}

// checkStale rejects an enrichment entry for a route the registry does not
// serve — the failure mode a hand-written spec dies of.
func checkStale(ops map[string]operationSource, used map[string]bool) error {
	var stale []string
	for key := range ops {
		if !used[key] {
			stale = append(stale, key)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	return fmt.Errorf("source operations name routes the registry does not serve: %s",
		strings.Join(stale, ", "))
}

// methodsOf returns the methods a route accepts. An empty registry method set
// means the handler dispatches for itself; the honest documentation of that
// is the full set the registry would otherwise gate.
func methodsOf(rt route.Policy) []string {
	if len(rt.Methods) > 0 {
		return rt.Methods
	}
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
}

// defaultTemplate documents a prefix route (a path ending in "/") the source
// has not named. The trailing segment is real but unnamed, so it is
// documented as such rather than dropped.
func defaultTemplate(path string) string {
	if strings.HasSuffix(path, "/") && path != "/" {
		return path + "{subpath}"
	}
	return path
}

func pathParameters(docPath string) []any {
	var params []any
	for seg := range strings.SplitSeq(docPath, "/") {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := strings.Trim(seg, "{}")
		description := "Path parameter."
		if name == "subpath" {
			description = "Trailing path segment; this route matches by prefix."
		}
		params = append(params, map[string]any{
			"name":        name,
			"in":          "path",
			"required":    true,
			"description": description,
			"schema":      map[string]any{"type": "string"},
		})
	}
	return params
}

// newOperation renders what the registry knows about one method on one route.
// Every response listed is one the composed middleware can actually return.
func newOperation(rt route.Policy, method, docPath string) operation {
	mutating := !safeMethod(method)

	responses := map[string]any{
		"500": errorResponse("Internal error."),
	}
	if rt.Auth {
		responses["401"] = errorResponse("Missing or invalid bearer token.")
	}
	if rt.CSRF && mutating {
		responses["403"] = errorResponse("Missing or invalid CSRF token.")
	}
	// Scope gates exempt safe methods, so a scoped route's GET is readable by
	// any admitted caller — the same shape as the CSRF branch above.
	if rt.Scope != "" && mutating {
		refusal := capitalize(rt.Scope) + " scope required."
		if rt.CSRF {
			refusal = capitalize(rt.Scope) + " scope required, or CSRF token missing or invalid."
		}
		responses["403"] = errorResponse(refusal)
	}
	if rt.RateLimited {
		responses["429"] = errorResponse("Rate limit exceeded for this route class.")
	}
	if rt.MaxBodyBytes > 0 && mutating {
		responses["413"] = errorResponse(
			fmt.Sprintf("Request body larger than %d bytes.", rt.MaxBodyBytes))
	}
	if len(rt.Methods) > 0 {
		responses["405"] = errorResponse("Method not allowed; the Allow header lists the accepted set.")
	}

	op := operation{
		"operationId": operationID(docPath, method),
		"responses":   responses,
	}
	switch {
	case !rt.Auth:
		op["security"] = []any{}
	case rt.CSRF && mutating:
		op["security"] = []any{
			map[string]any{BearerAuth: []any{}, CSRFToken: []any{}},
		}
	}
	if rt.Scope != "" && mutating {
		op["description"] = "Requires " + article(rt.Scope) + " " + rt.Scope + "-scoped token."
	}
	return op
}

func safeMethod(m string) bool { return m == "GET" || m == "HEAD" || m == "OPTIONS" }

func capitalize(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

func article(word string) string {
	if strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}

func errorResponse(description string) map[string]any {
	return map[string]any{
		"description": description,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/Error"},
			},
		},
	}
}

// operationID builds a stable, unique id from the method and path so
// generated clients get usable names and the document diffs cleanly.
func operationID(path, method string) string {
	var id strings.Builder
	id.WriteString(strings.ToLower(method))
	for seg := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		seg = strings.Trim(seg, "{}")
		if seg == "" {
			continue
		}
		for _, part := range strings.FieldsFunc(seg, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			id.WriteString(strings.ToUpper(part[:1]))
			id.WriteString(part[1:])
		}
	}
	return id.String()
}
