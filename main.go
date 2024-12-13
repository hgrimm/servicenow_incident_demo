package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Datenstruktur für die Antwort des ServiceNow Incident-Endpunkts
type ServiceNowIncidentResp struct {
	Result struct {
		Number string `json:"number"`
	} `json:"result"`
}

func openURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		// Unter Windows: cmd /c start "" <URL>
		cmd = "cmd"
		args = []string{"/c", "start", "", url}
	case "darwin":
		// Auf macOS: open <URL>
		cmd = "open"
		args = []string{url}
	default:
		if isWSL() {
			// Unter WSL: cmd.exe /c start "" <URL>
			cmd = "cmd.exe"
			args = []string{"/c", "start", "", url}
		} else {
			// Auf Linux: xdg-open <URL>
			cmd = "xdg-open"
			args = []string{url}
		}
	}

	return exec.Command(cmd, args...).Start()
}

// isWSL prüft, ob der Code in der Windows Subsystem for Linux Umgebung läuft.
func isWSL() bool {
	releaseData, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(releaseData)), "microsoft")
}

func main() {
	// HTML-Formular-Template
	formTemplate := `
<!DOCTYPE html>
<html lang="de">
<head>
	<meta charset="UTF-8">
	<title>ServiceNow Incident erstellen</title>
</head>
<body>
	<h1>Neues Incident erstellen</h1>
	<form action="/submit" method="post">
		<label for="short_description">short_description:</label><br>
		<input type="text" id="short_description" name="short_description" required><br><br>

		<label for="category">category:</label><br>
		<input type="text" id="category" name="category" value="software"><br><br>

		<label for="subcategory">subcategory:</label><br>
		<input type="text" id="subcategory" name="subcategory" value="email"><br><br>

		<label for="urgency">urgency:</label><br>
		<input type="text" id="urgency" name="urgency" value="2"><br><br>

		<label for="impact">impact:</label><br>
		<input type="text" id="impact" name="impact" value="2"><br><br>

		<label for="caller_id">caller_id:</label><br>
		<input type="text" id="caller_id" name="caller_id" value="8fe6a1a983821210e5f1b3a6feaad309"><br><br>

		<label for="description">description:</label><br>
		<textarea id="description" name="description"></textarea><br><br>

		<label for="cmdb_ci">cmdb_ci:</label><br>
		<input type="text" id="cmdb_ci" name="cmdb_ci" value="ded5656983821210e5f1b3a6feaad3c6"><br><br>

		<hr>
		<p>Anmeldedaten:</p>

		<label for="username">username (optional, falls kein API Key):</label><br>
		<input type="text" id="username" name="username"><br><br>

		<label for="password">password (optional, falls kein API Key):</label><br>
		<input type="password" id="password" name="password"><br><br>

		<label for="apikey">API-Key (optional, falls kein Benutzername/Passwort):</label><br>
		<input type="text" id="apikey" name="apikey"><br><br>

		<input type="submit" value="Incident erstellen">
	</form>
</body>
</html>
`

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t := template.Must(template.New("form").Parse(formTemplate))
		err := t.Execute(w, nil)
		if err != nil {
			fmt.Printf("Error rendering template: %v\n", err)
		}
	})

	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
			return
		}

		// Form-Daten auslesen
		shortDescription := r.FormValue("short_description")
		category := r.FormValue("category")
		subcategory := r.FormValue("subcategory")
		urgency := r.FormValue("urgency")
		impact := r.FormValue("impact")
		callerID := r.FormValue("caller_id")
		description := r.FormValue("description")
		cmdbCI := r.FormValue("cmdb_ci")
		username := r.FormValue("username")
		password := r.FormValue("password")
		apikey := r.FormValue("apikey")

		url := "https://dev247807.service-now.com/api/now/table/incident"
		fmt.Printf("URL: %s\n", url)

		// Payload erstellen
		payload := map[string]interface{}{
			"short_description": shortDescription,
			"category":          category,
			"subcategory":       subcategory,
			"urgency":           urgency,
			"impact":            impact,
			"caller_id":         callerID,
			"description":       description,
			"cmdb_ci":           cmdbCI,
		}

		// JSON erstellen
		jsonData, err := json.Marshal(payload)
		if err != nil {
			fmt.Printf("Fehler beim JSON-Encoding: %v\n", err)
			http.Error(w, "Fehler beim Erstellen des Requests", http.StatusInternalServerError)
			return
		}

		// HTTP-Request erstellen
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("Fehler beim Erstellen des Requests: %v\n", err)
			http.Error(w, "Fehler beim Erstellen des Requests", http.StatusInternalServerError)
			return
		}

		// Header setzen
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		if username != "" && password != "" {
			fmt.Printf("Benutzername und Passwort werden verwendet\n")
			req.SetBasicAuth(username, password)
		} else if apikey != "" {
			fmt.Printf("API-Key wird verwendet\n")
			req.Header.Set("X-sn-apikey", apikey)
		} else {
			fmt.Printf("Fehler: Weder Benutzer/Passwort noch API-Key\n")
			http.Error(w, "Authentifizierungsdaten fehlen", http.StatusBadRequest)
			return
		}

		client := &http.Client{}

		// Request abschicken
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Fehler beim Senden des Requests: %v\n", err)
			http.Error(w, "Fehler beim Senden des Requests", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Antwort lesen
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Fehler beim Lesen der Antwort: %v\n", err)
			http.Error(w, "Fehler beim Lesen der Antwort", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Response Status: %s\n", resp.Status)
		fmt.Printf("Response Body: %s\n", string(body))

		var serviceNowResp ServiceNowIncidentResp
		err = json.Unmarshal(body, &serviceNowResp)
		if err != nil {
			fmt.Printf("Fehler beim Parsen der Antwort: %v\n", err)
			http.Error(w, "Fehler beim Verarbeiten der Antwort", http.StatusInternalServerError)
			return
		}

		if serviceNowResp.Result.Number == "" {
			fmt.Printf("Fehler: Keine Incident-Nummer im Response\n")
			http.Error(w, "Fehler: Incident-Nummer fehlt im ServiceNow-Response", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Incident erstellt: %s\n", serviceNowResp.Result.Number)

		// Erfolgreiche Ausgabe für den Nutzer
		fmt.Fprintf(w, "Incident wurde erfolgreich erstellt: %s", serviceNowResp.Result.Number)
	})

	// call openURL to open the browser with the URL localhost:8080 after the server is started
	go openURL("http://localhost:8080")

	// Server auf Port 8080 starten
	port := ":8080"
	fmt.Printf("Starte Server auf %s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Printf("Fehler beim Starten des Servers: %v\n", err)
		os.Exit(1)
	}
}
