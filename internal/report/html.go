package report

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/AlejandroMolines/depsentinel/internal/model"
	"github.com/AlejandroMolines/depsentinel/web"
)

const dataMarker = `<script id="ds-data" type="application/json">null</script>`

// HTML devuelve el panel autocontenido con el informe incrustado.
// json.Marshal escapa <, > y & (\u003c...), así que el JSON es seguro dentro de una etiqueta <script>.
func HTML(rep *model.Report) ([]byte, error) {
	data, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	return injectHTML(data)
}

// HTMLFromJSON incrusta un informe JSON ya generado (por ejemplo, el de `scan --format json`).
func HTMLFromJSON(raw []byte) ([]byte, error) {
	var rep model.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, errors.New("el fichero no es un informe JSON de DepSentinel: " + err.Error())
	}
	if rep.Tool != "depsentinel" {
		return nil, errors.New("el fichero no es un informe de DepSentinel (falta \"tool\": \"depsentinel\")")
	}
	return HTML(&rep)
}

func injectHTML(data []byte) ([]byte, error) {
	tpl := string(web.DashboardHTML)
	if !strings.Contains(tpl, dataMarker) {
		return nil, errors.New("la plantilla del panel no tiene el marcador de datos")
	}
	repl := `<script id="ds-data" type="application/json">` + string(data) + `</script>`
	return []byte(strings.Replace(tpl, dataMarker, repl, 1)), nil
}
