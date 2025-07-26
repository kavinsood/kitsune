package pipeline

// ParsedPattern represents a pattern split into regex and commands.
type ParsedPattern struct {
	Regex    string            `json:"regex"`
	Commands map[string]string `json:"commands,omitempty"`
}

type Fingerprint struct {
	// --- Existing Fields ---
	CSS       []ParsedPattern            `json:"css,omitempty"`
	Cookies   map[string]ParsedPattern   `json:"cookies,omitempty"`
	JS        map[string]ParsedPattern   `json:"js,omitempty"`
	Headers   map[string]ParsedPattern   `json:"headers,omitempty"`
	HTML      []ParsedPattern            `json:"html,omitempty"`
	Script    []ParsedPattern            `json:"scripts,omitempty"`
	ScriptSrc []ParsedPattern            `json:"scriptSrc,omitempty"`
	Meta      map[string][]ParsedPattern `json:"meta,omitempty"`

	Implies     []string `json:"implies,omitempty"`
	Cats        []int    `json:"cats,omitempty"`
	Description string   `json:"description,omitempty"`
	Website     string   `json:"website,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	CPE         string   `json:"cpe,omitempty"`

	// --- NEW FIELDS ---
	URL        []ParsedPattern          `json:"url,omitempty"`
	Robots     []ParsedPattern          `json:"robots,omitempty"`
	DOM        []ParsedPattern          `json:"dom,omitempty"`
	DNS        map[string]ParsedPattern `json:"dns,omitempty"`
	CertIssuer map[string]ParsedPattern `json:"certIssuer,omitempty"`
}

type Fingerprints struct {
	Apps map[string]Fingerprint `json:"apps"`
}
