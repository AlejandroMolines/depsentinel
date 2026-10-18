package report

import (
	"encoding/json"
	"io"

	"github.com/AlejandroMolines/depsentinel/internal/model"
)

// JSON escribe el informe completo en JSON con sangría.
func JSON(w io.Writer, rep *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
