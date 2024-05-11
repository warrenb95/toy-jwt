package http

import (
	"html/template"
	"net/http"

	"github.com/sirupsen/logrus"
)

func Index(logger *logrus.Logger, tmpl *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logger.WithContext(r.Context())

		if err := tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
			logger.WithError(err).Error("Failed to execute index template")
			http.Error(w, "failed to execute index template", http.StatusInternalServerError)
			return
		}
	}
}
