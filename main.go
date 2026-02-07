package main

import (	
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "os/user"      // Changed: using os/user instead
    "path/filepath"  
    "runtime"        
    "strings"
    "time"
	"bytes"
	"crypto/tls"
	"flag"
	"text/tabwriter"
)

// GanetiClient handles all RAPI communication
type GanetiClient struct {
	baseURL string
	client  *http.Client
	user    string
	pass    string
}

type Config struct {
    AuthIssuer   string `json:"auth_issuer"`
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
    AccessToken  string `json:"access_token"`
    ExpiresAt    string `json:"expires_at"`
}

// Instance represents a Ganeti instance (simplified view)
type Instance struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"`
	Primary   string        `json:"pnode"`
	Secondary []string      `json:"snodes"`
	OS        string        `json:"os,omitempty"`
	Tags      []string      `json:"tags,omitempty"`
	HVParams  interface{}   `json:"hvparams,omitempty"`
	BeParams  BeParams      `json:"beparams,omitempty"`
	Disks     []interface{} `json:"disks,omitempty"`
	Nics      []interface{} `json:"nics,omitempty"`
}

// BeParams holds instance resource parameters
type BeParams struct {
	Memory int `json:"memory,omitempty"`
	Vcpus  int `json:"vcpus,omitempty"`
}

// Node represents a Ganeti node (simplified view)
type Node struct {
	Name        string   `json:"name"`
	Role        string   `json:"role,omitempty"`
	Offline     bool     `json:"offline,omitempty"`
	Master      bool     `json:"master,omitempty"`
	Drained     bool     `json:"drained,omitempty"`
	TotalMemory int      `json:"mtotal,omitempty"`
	FreeMemory  int      `json:"mfree,omitempty"`
	TotalDisk   int      `json:"dtotal,omitempty"`
	FreeDisk    int      `json:"dfree,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Cluster represents cluster info (simplified)
type Cluster struct {
	Name          string   `json:"name"`
	UUID          string   `json:"uuid,omitempty"`
	Master        string   `json:"master,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	InstanceCount int      `json:"instance_count,omitempty"`
	NodeCount     int      `json:"node_count,omitempty"`
}

// Job represents a Ganeti job (simplified)
type Job struct {
	ID       int           `json:"id"`
	Status   string        `json:"status"`
	Ops      []interface{} `json:"ops"`
	OpLog    []interface{} `json:"op_log"`
	Priority int           `json:"priority"`
	Received []float64     `json:"received_ts,omitempty"`
	Started  []float64     `json:"start_ts,omitempty"`
	Ended    []float64     `json:"end_ts,omitempty"`
}

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    Scope        string `json:"scope"`
}

// ConfigPath returns the platform-appropriate config file path
func ConfigPath() string {
    var configDir string
    
    if runtime.GOOS == "windows" {
        configDir = os.Getenv("APPDATA")
        if configDir == "" {
            // Fallback for Windows
            usr, err := user.Current()
            if err != nil {
                fmt.Fprintf(os.Stderr, "Error getting user info: %v\n", err)
                os.Exit(1)
            }
            configDir = filepath.Join(usr.HomeDir, "AppData", "Roaming")
        }
    } else {
        // Unix-like systems (Linux, macOS, etc.)
        usr, err := user.Current()
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error getting user info: %v\n", err)
            os.Exit(1)
        }
        configDir = filepath.Join(usr.HomeDir, ".config")
    }
    
    return filepath.Join(configDir, "ganetigo", "config.json")
}

// LoadConfig reads the config file and returns the Config struct
func LoadConfig() (Config, error) {
    var config Config
    
    configPath := ConfigPath()
    
    // If file doesn't exist, return empty config (not an error)
    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        return config, nil
    }
    
    data, err := os.ReadFile(configPath)
    if err != nil {
        return config, fmt.Errorf("failed to read config file: %w", err)
    }
    
    if err := json.Unmarshal(data, &config); err != nil {
        return config, fmt.Errorf("failed to parse config file: %w", err)
    }
    
    return config, nil
}

// SaveConfig writes the Config struct to the config file
func SaveConfig(config Config) error {
    configPath := ConfigPath()
    
    // Create directory if it doesn't exist
    configDir := filepath.Dir(configPath)
    if err := os.MkdirAll(configDir, 0755); err != nil {
        return fmt.Errorf("failed to create config directory: %w", err)
    }
    
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }
    
    if err := os.WriteFile(configPath, data, 0600); err != nil {
        return fmt.Errorf("failed to write config file: %w", err)
    }
    
    return nil
}

func cmdAuthLogin() {
    var username, password string
    
    // Prompt for username
    fmt.Print("Username: ")
    fmt.Scanln(&username)
    
    // Prompt for password
    fmt.Print("Password: ")
    fmt.Scanln(&password)
    
    // Hard-code the configuration values for first-time use
    authIssuer := "http://localhost:9000/application/o/ganetigo-cli/"
    clientID := "divpdt0B6mvT4xD0Yz2610YfaVCLnm6TITGHIwid"
    clientSecret := "TJO89mZMqsFeavWtYcB8EIdCwWfxqUQlwQgZnNowTtTXNuaGxLGDElowp9SIDBNEGg5Rj829zY4P2Ikyo30iv7fHBMMZ56IFwOuXtmtvJKubv5MnGU4NZMFFh8R4N6js"  
    
    // Prepare token endpoint URL
    tokenEndpoint := "http://localhost:9000/application/o/token/"
    
    // Prepare request body using url.Values for form encoding
    data := url.Values{}
    data.Set("grant_type", "password")
    data.Set("client_id", clientID)
    data.Set("client_secret", clientSecret)
    data.Set("username", username)
    data.Set("password", password)
    data.Set("scope", "openid profile email")
    
    // Make POST request to token endpoint using net/http
    resp, err := http.Post(
        tokenEndpoint,
        "application/x-www-form-urlencoded",
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
        os.Exit(1)
    }
    
    // Check for HTTP errors
    if resp.StatusCode != http.StatusOK {
        fmt.Fprintf(os.Stderr, "Authentication failed: %s\n", string(body))
        os.Exit(1)
    }
    
    // Parse token response using encoding/json
    var tokenResp TokenResponse
    if err := json.Unmarshal(body, &tokenResp); err != nil {
        fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
        os.Exit(1)
    }
    
    // Calculate expiry time
    expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
    
    // Create config with all values
    config := Config{
        AuthIssuer:   authIssuer,
        ClientID:     clientID,
        ClientSecret: clientSecret,
        AccessToken:  tokenResp.AccessToken,
        ExpiresAt:    expiresAt.Format(time.RFC3339),
    }
    
    // Save config (this will create the file and directory if needed)
    if err := SaveConfig(config); err != nil {
        fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Println("Logged in successfully!")
}

func cmdAuthStatus() {
    config, err := LoadConfig()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
        os.Exit(1)
    }
    
    // Check if token exists
    if config.AccessToken == "" {
        fmt.Println("Not logged in. Run 'ganetigo auth login' to authenticate.")
        return
    }
    
    // Check if token is expired
    expiresAt, err := time.Parse(time.RFC3339, config.ExpiresAt)
    if err != nil {
        fmt.Println("Not logged in. Run 'ganetigo auth login' to authenticate.")
        return
    }
    
    if time.Now().After(expiresAt) {
        fmt.Println("Login expired. Run 'ganetigo auth login' to re-authenticate.")
        return
    }
    
    fmt.Printf("Logged in (token expires at %s)\n", expiresAt.Format("2006-01-02 15:04:05"))
}

func requireLogin() {
    config, err := LoadConfig()
    if err != nil || config.AccessToken == "" {
        fmt.Fprintln(os.Stderr, "Error: Not logged in.")
        fmt.Fprintln(os.Stderr, "Run 'ganetigo auth login' to authenticate.")
        os.Exit(1)
    }
    
    expiresAt, err := time.Parse(time.RFC3339, config.ExpiresAt)
    if err != nil || time.Now().After(expiresAt) {
        fmt.Fprintln(os.Stderr, "Error: Login expired.")
        fmt.Fprintln(os.Stderr, "Run 'ganetigo auth login' to re-authenticate.")
        os.Exit(1)
    }
}

// helper to convert Ganeti timestamp array [sec, usec] to time.Time
func tsToTime(ts []float64) *time.Time {
	if len(ts) < 1 {
		return nil
	}
	sec := int64(ts[0])
	var nsec int64
	if len(ts) > 1 {
		nsec = int64(ts[1] * 1000) // microseconds to nanoseconds
	}
	t := time.Unix(sec, nsec)
	return &t
}

// NewGanetiClient creates a new Ganeti RAPI client
func NewGanetiClient(baseURL string) *GanetiClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
	}

	if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasSuffix(baseURL, "/2") {
		baseURL = baseURL + "/2"
	}

	// default creds for this test cluster (override via env)
	user := os.Getenv("GANETI_USER")
	pass := os.Getenv("GANETI_PASS")
	if user == "" {
		user = "gnt-cc"
	}
	if pass == "" {
		pass = "gnt-cc"
	}

	return &GanetiClient{
		baseURL: baseURL,
		client:  client,
		user:    user,
		pass:    pass,
	}
}

// request makes an HTTP request to the RAPI
func (gc *GanetiClient) request(method, endpoint string, body io.Reader) ([]byte, error) {
	url := gc.baseURL + endpoint

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Basic auth (needed for writes; harmless for reads)
	if gc.user != "" {
		req.SetBasicAuth(gc.user, gc.pass)
	}

	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// ListInstances returns a list of all instance names
func (gc *GanetiClient) ListInstances() ([]string, error) {
	body, err := gc.request("GET", "/instances?bulk=1", nil)
	if err != nil {
		return nil, err
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse instances: %w", err)
	}

	names := make([]string, 0, len(raw))
	for _, inst := range raw {
		if name, ok := inst["name"].(string); ok {
			names = append(names, name)
		}
	}

	return names, nil
}

// GetInstance returns details for a specific instance
func (gc *GanetiClient) GetInstance(name string) (*Instance, error) {
	body, err := gc.request("GET", "/instances/"+name, nil)
	if err != nil {
		return nil, err
	}

	var inst Instance
	if err := json.Unmarshal(body, &inst); err != nil {
		return nil, fmt.Errorf("failed to parse instance: %w", err)
	}

	return &inst, nil
}

// InstanceAction performs an action on an instance (startup, shutdown, reboot)
func (gc *GanetiClient) InstanceAction(name, action string) (int, error) {
	endpoint := fmt.Sprintf("/instances/%s/%s", name, action)

	// Instance actions use PUT in Ganeti RAPI
	body, err := gc.request("PUT", endpoint, nil)
	if err != nil {
		return 0, err
	}

	// Some Ganeti versions return just the job ID as a JSON number, e.g. 17
	var jobIDNumber int
	if err := json.Unmarshal(body, &jobIDNumber); err == nil {
		return jobIDNumber, nil
	}

	// Others return an object like {"job_id": 17} or {"job": 17}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}

	if jid, ok := result["job_id"].(float64); ok {
		return int(jid), nil
	}
	if jid, ok := result["job"].(float64); ok {
		return int(jid), nil
	}

	return 0, fmt.Errorf("no job ID in response")
}

// DeleteInstance deletes an instance
func (gc *GanetiClient) DeleteInstance(name string) (int, error) {
	body, err := gc.request("DELETE", "/instances/"+name, nil)
	if err != nil {
		return 0, err
	}

	// Allow plain number or object
	var jobIDNumber int
	if err := json.Unmarshal(body, &jobIDNumber); err == nil {
		return jobIDNumber, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("failed to parse delete response: %w", err)
	}

	if jid, ok := result["job_id"].(float64); ok {
		return int(jid), nil
	}
	if jid, ok := result["job"].(float64); ok {
		return int(jid), nil
	}

	return 0, fmt.Errorf("no job ID in response")
}

// CreateInstance creates a new instance (diskless, fake hypervisor, noop OS)
func (gc *GanetiClient) CreateInstance(name, primaryNode string, memory, vcpus int) (int, error) {
	if primaryNode == "" {
		return 0, fmt.Errorf("primary node is required")
	}
	if memory <= 0 {
		memory = 128
	}
	if vcpus <= 0 {
		vcpus = 1
	}

	// Versioned create request (v1). RAPI still requires 'disks' and 'nics'
	// even for diskless instances; we pass empty lists to satisfy validation.
	payload := map[string]interface{}{
		"__version__":   1,
		"instance_name": name,
		"mode":          "create",
		"start":         false,
		"pnode":         primaryNode,
		"disk_template": "diskless",
		"hypervisor":    "fake",
		"os_type":       "noop",
		"disks":         []interface{}{},
		"nics":          []interface{}{},
		"beparams": map[string]interface{}{
			"memory": memory,
			"vcpus":  vcpus,
		},
		"ip_check":        false,
		"name_check":      false,
		"conflicts_check": false,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal create payload: %w", err)
	}

	body, err := gc.request("POST", "/instances", bytes.NewReader(data))
	if err != nil {
		return 0, err
	}

	// Accept both plain number and object forms
	var jobIDNumber int
	if err := json.Unmarshal(body, &jobIDNumber); err == nil {
		return jobIDNumber, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("failed to parse create response: %w", err)
	}

	if jid, ok := result["job_id"].(float64); ok {
		return int(jid), nil
	}
	if jid, ok := result["job"].(float64); ok {
		return int(jid), nil
	}

	return 0, fmt.Errorf("no job ID in response")
}

// ListNodes returns a list of all node names
func (gc *GanetiClient) ListNodes() ([]string, error) {
	body, err := gc.request("GET", "/nodes?bulk=1", nil)
	if err != nil {
		return nil, err
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse nodes: %w", err)
	}

	names := make([]string, 0, len(raw))
	for _, node := range raw {
		if name, ok := node["name"].(string); ok {
			names = append(names, name)
		}
	}

	return names, nil
}

// GetNode returns details for a specific node
func (gc *GanetiClient) GetNode(name string) (*Node, error) {
	body, err := gc.request("GET", "/nodes/"+name, nil)
	if err != nil {
		return nil, err
	}

	var node Node
	if err := json.Unmarshal(body, &node); err != nil {
		return nil, fmt.Errorf("failed to parse node: %w", err)
	}

	return &node, nil
}

// GetClusterInfo returns cluster information
func (gc *GanetiClient) GetClusterInfo() (*Cluster, error) {
	body, err := gc.request("GET", "/info", nil)
	if err != nil {
		return nil, err
	}

	var cluster Cluster
	if err := json.Unmarshal(body, &cluster); err != nil {
		return nil, fmt.Errorf("failed to parse cluster info: %w", err)
	}

	return &cluster, nil
}

// GetJob returns details for a specific job
func (gc *GanetiClient) GetJob(jobID int) (*Job, error) {
	body, err := gc.request("GET", fmt.Sprintf("/jobs/%d", jobID), nil)
	if err != nil {
		return nil, err
	}

	var job Job
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("failed to parse job: %w", err)
	}

	return &job, nil
}

// confirm prompts the user for yes/no on stdin
func confirm(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var answer string
	_, err := fmt.Scanln(&answer)
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// ================= CLI Command Handlers =================

func cmdInstanceList(client *GanetiClient) {
	instances, err := client.ListInstances()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(instances) == 0 {
		fmt.Println("No instances found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tNODE\tMEMORY\tVCPUS")

	for _, name := range instances {
		inst, err := client.GetInstance(name)
		if err != nil {
			fmt.Fprintf(w, "%s\tERROR\t-\t-\t-\n", name)
			continue
		}

		mem := "-"
		if inst.BeParams.Memory > 0 {
			mem = fmt.Sprintf("%dM", inst.BeParams.Memory)
		}
		vcpus := "-"
		if inst.BeParams.Vcpus > 0 {
			vcpus = fmt.Sprintf("%d", inst.BeParams.Vcpus)
		}
		node := inst.Primary
		if node == "" {
			node = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", inst.Name, inst.Status, node, mem, vcpus)
	}

	w.Flush()
}

func cmdInstanceInfo(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo instance info <instance-name>")
		os.Exit(1)
	}

	inst, err := client.GetInstance(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Name:       %s\n", inst.Name)
	fmt.Printf("Status:     %s\n", inst.Status)
	fmt.Printf("Primary:    %s\n", inst.Primary)
	if len(inst.Secondary) > 0 {
		fmt.Printf("Secondary:  %v\n", inst.Secondary)
	}
	fmt.Printf("Memory:     %d MB\n", inst.BeParams.Memory)
	fmt.Printf("VCPUs:      %d\n", inst.BeParams.Vcpus)
	fmt.Printf("OS:         %s\n", inst.OS)
	if len(inst.Tags) > 0 {
		fmt.Printf("Tags:       %v\n", inst.Tags)
	}
}

func cmdInstanceStart(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo instance start <instance-name>")
		os.Exit(1)
	}

	jobID, err := client.InstanceAction(args[0], "startup")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Started instance %s (Job ID: %d)\n", args[0], jobID)
}

func cmdInstanceStop(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo instance stop <instance-name>")
		os.Exit(1)
	}

	jobID, err := client.InstanceAction(args[0], "shutdown")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Stopped instance %s (Job ID: %d)\n", args[0], jobID)
}

func cmdInstanceRestart(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo instance restart <instance-name>")
		os.Exit(1)
	}

	jobID, err := client.InstanceAction(args[0], "reboot")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Restarted instance %s (Job ID: %d)\n", args[0], jobID)
}

func cmdInstanceDelete(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo instance delete <instance-name>")
		os.Exit(1)
	}

	name := args[0]

	inst, err := client.GetInstance(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting instance info: %v\n", err)
		os.Exit(1)
	}

	// If running, confirm stop + delete
	if strings.ToLower(inst.Status) == "running" {
		if !confirm(fmt.Sprintf("Instance %s is running. Are you sure you want to stop and delete it?", name)) {
			fmt.Println("Aborted.")
			return
		}

		jobID, err := client.InstanceAction(name, "shutdown")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping instance: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Stopping instance %s (Job ID: %d)\n", name, jobID)
	} else {
		// Not running: just confirm delete
		if !confirm(fmt.Sprintf("Are you sure you want to delete instance %s?", name)) {
			fmt.Println("Aborted.")
			return
		}
	}

	jobID, err := client.DeleteInstance(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting instance: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted instance %s (Job ID: %d)\n", name, jobID)
}

func cmdInstanceCreate(client *GanetiClient, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: ganetigo instance create <name> <primary-node> [--memory MB] [--vcpus N]")
		os.Exit(1)
	}

	name := args[0]
	primary := args[1]
	memory := 128
	vcpus := 1

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--memory":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &memory)
				i++
			}
		case "--vcpus":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &vcpus)
				i++
			}
		}
	}

	jobID, err := client.CreateInstance(name, primary, memory, vcpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created instance %s on %s (Job ID: %d)\n", name, primary, jobID)
}

func cmdNodeList(client *GanetiClient) {
	nodes, err := client.ListNodes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(nodes) == 0 {
		fmt.Println("No nodes found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tROLE\tOFFLINE\tDRAINED")

	for _, name := range nodes {
		node, err := client.GetNode(name)
		if err != nil {
			fmt.Fprintf(w, "%s\tERROR\t-\t-\n", name)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%v\t%v\n", node.Name, node.Role, node.Offline, node.Drained)
	}

	w.Flush()
}

func cmdNodeInfo(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo node info <node-name>")
		os.Exit(1)
	}

	node, err := client.GetNode(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Name:         %s\n", node.Name)
	fmt.Printf("Role:         %s\n", node.Role)
	fmt.Printf("Master:       %v\n", node.Master)
	fmt.Printf("Offline:      %v\n", node.Offline)
	fmt.Printf("Drained:      %v\n", node.Drained)
	if node.TotalMemory > 0 {
		fmt.Printf("Total Memory: %d MB\n", node.TotalMemory)
	}
	if node.FreeMemory > 0 {
		fmt.Printf("Free Memory:  %d MB\n", node.FreeMemory)
	}
	if node.TotalDisk > 0 {
		fmt.Printf("Total Disk:   %d MB\n", node.TotalDisk)
	}
	if node.FreeDisk > 0 {
		fmt.Printf("Free Disk:    %d MB\n", node.FreeDisk)
	}
}

func cmdClusterInfo(client *GanetiClient) {
	cluster, err := client.GetClusterInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Name:      %s\n", cluster.Name)
	fmt.Printf("Master:    %s\n", cluster.Master)
	if cluster.UUID != "" {
		fmt.Printf("UUID:      %s\n", cluster.UUID)
	}
	if len(cluster.Tags) > 0 {
		fmt.Printf("Tags:      %v\n", cluster.Tags)
	}
	if cluster.InstanceCount > 0 {
		fmt.Printf("Instances: %d\n", cluster.InstanceCount)
	}
	if cluster.NodeCount > 0 {
		fmt.Printf("Nodes:     %d\n", cluster.NodeCount)
	}
}

func cmdJobInfo(client *GanetiClient, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ganetigo job info <job-id>")
		os.Exit(1)
	}

	var jobID int
	if _, err := fmt.Sscanf(args[0], "%d", &jobID); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid job ID: %v\n", err)
		os.Exit(1)
	}

	job, err := client.GetJob(jobID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Job ID:   %d\n", job.ID)
	fmt.Printf("Status:   %s\n", job.Status)
	fmt.Printf("Priority: %d\n", job.Priority)
	fmt.Printf("Ops:      %d\n", len(job.Ops))

	if t := tsToTime(job.Received); t != nil {
		fmt.Printf("Received: %v\n", *t)
	}
	if t := tsToTime(job.Started); t != nil {
		fmt.Printf("Started:  %v\n", *t)
	}
	if t := tsToTime(job.Ended); t != nil {
		fmt.Printf("Ended:    %v\n", *t)
	}
}

func showHelp() {
	fmt.Println("Usage: ganetigo [options] <command> [<args>]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -host string    Ganeti RAPI host (default: localhost:5080)")
	fmt.Println("  -help           Show this help message")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  auth <subcommand>")
	fmt.Println("    login         Authenticate with authentik")
	fmt.Println("    status        Check authentication status")
	fmt.Println()
	fmt.Println("  instance <subcommand> [args...]")
	fmt.Println("    list          List all instances (requires auth)")
	fmt.Println("    info <name>   Show instance information")
	fmt.Println("    start <name>  Start instance (requires auth)")
	fmt.Println("    stop <name>   Stop instance (requires auth)")
	fmt.Println("    restart <name> Restart instance")
	fmt.Println("    delete <name>  Delete instance")
	fmt.Println("    create        Create new instance")
	fmt.Println()
	fmt.Println("  node <subcommand> [args...]")
	fmt.Println("    list          List all nodes")
	fmt.Println("    info <name>   Show node information")
	fmt.Println()
	fmt.Println("  cluster <subcommand>")
	fmt.Println("    info          Show cluster information")
	fmt.Println()
	fmt.Println("  job <subcommand> [args...]")
	fmt.Println("    info <id>     Show job information")
}

func main() {
	hostFlag := flag.String("host", os.Getenv("GANETI_HOST"), "Ganeti RAPI host (default: localhost:5080)")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *helpFlag || flag.NArg() == 0 {
		showHelp()
		return
	}

	args := flag.Args()
	command := args[0]

	// Handle auth command separately (doesn't need Ganeti client)
	if command == "auth" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: auth requires a subcommand (login or status)")
			os.Exit(1)
		}

		subcommand := args[1]
		switch subcommand {
		case "login":
			cmdAuthLogin()
		case "status":
			cmdAuthStatus()
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown auth subcommand: %s\n", subcommand)
			os.Exit(1)
		}
		return // Exit after handling auth command
	}

	// For all other commands, set up Ganeti client
	if *hostFlag == "" {
		*hostFlag = "localhost:5080"
	}

	client := NewGanetiClient(*hostFlag)

	var subcommand string
	var cmdArgs []string

	if len(args) > 1 {
		subcommand = args[1]
		if len(args) > 2 {
			cmdArgs = args[2:]
		}
	}

	switch command {
	case "instance":
		switch subcommand {
		case "list":
			requireLogin() // Add authentication check
			cmdInstanceList(client)
		case "info":
			cmdInstanceInfo(client, cmdArgs)
		case "start":
			requireLogin() // Add authentication check
			cmdInstanceStart(client, cmdArgs)
		case "stop":
			requireLogin() // Add authentication check
			cmdInstanceStop(client, cmdArgs)
		case "restart":
			cmdInstanceRestart(client, cmdArgs)
		case "delete":
			cmdInstanceDelete(client, cmdArgs)
		case "create":
			cmdInstanceCreate(client, cmdArgs)
		default:
			fmt.Printf("Unknown instance subcommand: %s\n", subcommand)
			os.Exit(1)
		}
	case "node":
		switch subcommand {
		case "list":
			cmdNodeList(client)
		case "info":
			cmdNodeInfo(client, cmdArgs)
		default:
			fmt.Printf("Unknown node subcommand: %s\n", subcommand)
			os.Exit(1)
		}
	case "cluster":
		switch subcommand {
		case "info":
			cmdClusterInfo(client)
		default:
			fmt.Printf("Unknown cluster subcommand: %s\n", subcommand)
			os.Exit(1)
		}
	case "job":
		switch subcommand {
		case "info":
			cmdJobInfo(client, cmdArgs)
		default:
			fmt.Printf("Unknown job subcommand: %s\n", subcommand)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}