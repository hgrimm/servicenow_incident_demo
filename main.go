package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// add flag for service server hostname
var (
	serviceNowHostname string
)

func init() {
	flag.StringVar(&serviceNowHostname, "hostname", "", "ServiceNow hostname. example: dev12345.service-now.com")
}

// Data structure for the response of the ServiceNow Incident endpoint
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
		// On Windows: cmd /c start "" <URL>
		cmd = "cmd"
		args = []string{"/c", "start", "", url}
	case "darwin":
		// On macOS: open <URL>
		cmd = "open"
		args = []string{url}
	default:
		if isWSL() {
			// On WSL: cmd.exe /c start "" <URL>
			cmd = "cmd.exe"
			args = []string{"/c", "start", "", url}
		} else {
			// On Linux: xdg-open <URL>
			cmd = "xdg-open"
			args = []string{url}
		}
	}

	return exec.Command(cmd, args...).Start()
}

// isWSL checks whether the code is running in a Windows Subsystem for Linux environment.
func isWSL() bool {
	releaseData, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(releaseData)), "microsoft")
}

func main() {
	flag.Parse()

	if serviceNowHostname == "" {
		fmt.Printf("Hostname must not be empty\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// HTML form template
	formTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Create a new ServiceNow Incident</title>
</head>
<body>
	<h1>Create a new Incident</h1>
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
		<p>Login credentials:</p>

		<label for="username">username (optional, if no API key):</label><br>
		<input type="text" id="username" name="username"><br><br>

		<label for="password">password (optional, if no API key):</label><br>
		<input type="password" id="password" name="password"><br><br>

		<label for="apikey">API key (optional, if no username/password):</label><br>
		<input type="text" id="apikey" name="apikey"><br><br>

		<input type="submit" value="Create Incident">
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
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read form data
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

		servicenowUrl := fmt.Sprintf("https://%s/api/now/table/incident", serviceNowHostname)

		fmt.Printf("Endpoint URL: %s\n", servicenowUrl)

		// Create payload
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

		// Create JSON
		jsonData, err := json.Marshal(payload)
		if err != nil {
			fmt.Printf("Error during JSON encoding: %v\n", err)
			http.Error(w, "Error creating the request", http.StatusInternalServerError)
			return
		}

		// Create HTTP request
		req, err := http.NewRequest("POST", servicenowUrl, bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("Error creating the request: %v\n", err)
			http.Error(w, "Error creating the request", http.StatusInternalServerError)
			return
		}

		// Set headers
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		if username != "" && password != "" {
			fmt.Printf("Using username and password\n")
			req.SetBasicAuth(username, password)
		} else if apikey != "" {
			fmt.Printf("Using API key\n")
			req.Header.Set("X-sn-apikey", apikey)
		} else {
			fmt.Printf("Error: Neither username/password nor API key provided\n")
			http.Error(w, "Authentication data missing", http.StatusBadRequest)
			return
		}

		client := &http.Client{}

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error sending the request: %v\n", err)
			http.Error(w, "Error sending the request", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Read response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading the response: %v\n", err)
			http.Error(w, "Error reading the response", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Response Status: %s\n", resp.Status)
		fmt.Printf("Response Body: %s\n", string(body))

		var serviceNowResp ServiceNowIncidentResp
		err = json.Unmarshal(body, &serviceNowResp)
		if err != nil {
			fmt.Printf("Error parsing the response: %v\n", err)
			http.Error(w, "Error processing the response", http.StatusInternalServerError)
			return
		}

		if serviceNowResp.Result.Number == "" {
			fmt.Printf("Error: No incident number in the response\n")
			http.Error(w, "Error: Incident number missing in ServiceNow response", http.StatusInternalServerError)
			return
		}

		fmt.Printf("Incident created: %s\n", serviceNowResp.Result.Number)

		// Successful output for the user
		fmt.Fprintf(w, "Incident was successfully created: %s", serviceNowResp.Result.Number)
	})

	localServerAddr := "localhost:8080"
	go openURL("http://" + localServerAddr)

	fmt.Printf("Starting server on %s\n", localServerAddr)
	err := http.ListenAndServe(localServerAddr, nil)
	if err != nil {
		fmt.Printf("Error starting the server: %v\n", err)
		os.Exit(1)
	}
}
