package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/internal/osv"
	"github.com/AlejandroMolines/depsentinel/internal/rules"
	"github.com/AlejandroMolines/depsentinel/internal/version"
)

// Result agrupa el informe y el inventario del que sale.
type Result struct {
	Report    *model.Report
	Inventory *Inventory
}

// Scan ejecuta un escaneo completo.
func Scan(ctx context.Context, o Options) (*Result, error) {
	o.defaults()
	inv, err := BuildInventory(o)
	if err != nil {
		return nil, err
	}
	now := o.Now().UTC()
	rep := &model.Report{
		Tool: "depsentinel", Version: version.Version, SchemaVersion: model.SchemaVersion,
		GeneratedAt: now, Target: inv.BaseDir, Ecosystems: inv.Ecosystems, Sources: inv.Sources,
		Offline: o.Offline, Warnings: append([]string(nil), inv.Warnings...),
	}
	if inv.ParseErrors > 0 {
		rep.Incomplete = true
	}
	if len(inv.Packages) > 0 || len(inv.Findings) > 0 {
		o.Log("Analizando %d paquetes (%s)…", len(inv.Packages), describeEcosystems(inv.Ecosystems))
	}
	rctx := &rules.Context{Now: now, Store: o.Store, Config: o.Config, Vulns: map[string][]*osv.Vuln{}}
	online := !o.Offline
	if !online {
		rep.Warnings = append(rep.Warnings, "Modo sin conexión: no se consultan OSV ni los registries (solo reglas locales).")
	}
	if online && !o.NoOSV {
		vulns, warns, bad := queryOSV(ctx, &o, inv.Packages)
		rctx.Vulns = vulns
		rep.Warnings = append(rep.Warnings, warns...)
		rep.Incomplete = rep.Incomplete || bad
	}
	if online && !o.NoRegistry {
		warns, bad := enrich(ctx, &o, inv.Packages)
		rep.Warnings = append(rep.Warnings, warns...)
		rep.Incomplete = rep.Incomplete || bad
	}
	var extra []model.Finding
	if online && o.Deep && !o.NoRegistry {
		f, warns, bad := deepScan(ctx, &o, inv.Packages)
		extra = f
		rep.Warnings = append(rep.Warnings, warns...)
		rep.Incomplete = rep.Incomplete || bad
	}

	findings := append([]model.Finding(nil), inv.Findings...)
	findings = append(findings, extra...)
	for _, p := range inv.Packages {
		findings = append(findings, rules.Evaluate(rctx, p)...)
	}
	findings = dedupeFindings(findings)

	for _, e := range o.Allowlist.ExpiredEntries(now) {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("La excepción de %s caducó el %s (motivo original: %s); vuelve a evaluarse.", e.Name, e.Expires, e.Reason))
	}
	for _, f := range findings {
		if e, ok := o.Allowlist.Match(f, now); ok {
			f.Allowed = &model.AllowedInfo{Reason: e.Reason, Added: e.Added, Expires: e.Expires}
			rep.Suppressed = append(rep.Suppressed, f)
			continue
		}
		rep.Findings = append(rep.Findings, f)
	}
	rep.BuildSummary(inv.Packages)
	return &Result{Report: rep, Inventory: inv}, nil
}

// dedupeFindings elimina hallazgos idénticos (por ejemplo, un fichero incluido con -r y analizado también por separado).
func dedupeFindings(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		k := strings.Join([]string{f.Rule, f.ID, string(f.Ecosystem), f.Package, f.Version, f.Source, strconv.Itoa(f.Line), f.Title}, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// Elapsed es un utilitario para medir y mostrar la duración.
func Elapsed(start time.Time) string {
	d := time.Since(start)
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1f s", d.Seconds())
}
