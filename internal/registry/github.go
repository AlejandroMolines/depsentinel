package registry

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/httpx"
)

// DefaultGitHubAPI es la API REST de GitHub.
const DefaultGitHubAPI = "https://api.github.com"

// GitHub resuelve referencias de Git a SHAs de commit.
type GitHub struct {
	HTTP  *httpx.Client
	Base  string
	Token string
}

// NewGitHub crea un cliente de GitHub; usa GITHUB_TOKEN/GH_TOKEN si existe (solo para subir el límite de uso).
func NewGitHub(h *httpx.Client, base string) *GitHub {
	if base == "" {
		base = DefaultGitHubAPI
	}
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		tok = os.Getenv("GH_TOKEN")
	}
	return &GitHub{HTTP: h, Base: strings.TrimRight(base, "/"), Token: tok}
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ResolveRef devuelve el SHA del commit al que apunta una etiqueta, rama o SHA.
func (g *GitHub) ResolveRef(ctx context.Context, owner, repo, ref string) (string, error) {
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if g.Token != "" {
		headers["Authorization"] = "Bearer " + g.Token
	}
	u := fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.Base, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))
	var out struct {
		SHA string `json:"sha"`
	}
	if err := g.HTTP.GetJSON(ctx, u, headers, &out); err != nil {
		return "", err
	}
	if !shaRe.MatchString(out.SHA) {
		return "", fmt.Errorf("GitHub devolvió un SHA inesperado para %s/%s@%s", owner, repo, ref)
	}
	return out.SHA, nil
}
