package request

// Request represents an HTTP request variant that hax reasons about.
// It is the core domain type passed through the pipeline:
// generator -> mutation -> executor -> predicate.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Auth    string            `json:"auth,omitempty"`
	Origin  string            `json:"origin,omitempty"`
	Repeat  int               `json:"repeat,omitempty"`
	BaseURL string            `json:"base_url,omitempty"`
}
