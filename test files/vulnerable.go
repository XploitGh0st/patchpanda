// Vulnerable Go Test Code for Patch Panda
// DO NOT USE IN PRODUCTION!

package main

import (
    "crypto/md5"
    "database/sql"
    "fmt"
    "html/template"
    "io/ioutil"
    "log"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "time"
    "unsafe"

    _ "github.com/go-sql-driver/mysql"
)

// 1. HARDCODED SECRETS
const (
    APIKey     = "sk-go123456789"
    DBPassword = "admin123"
    JWTSecret  = "myGoSecret2024"
)

// 2. SQL INJECTION
func getUserData(userID string) (*sql.Rows, error) {
    db, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(localhost:3306)/myapp", DBPassword))
    if err != nil {
        return nil, err
    }
    defer db.Close()

    // VULNERABLE: String concatenation in SQL
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
    return db.Query(query)
}

// 3. COMMAND INJECTION
func pingHost(hostname string) error {
    // VULNERABLE: Direct command execution
    cmd := exec.Command("ping", "-c", "3", hostname)
    return cmd.Run()
}

func executeShell(userInput string) error {
    // VULNERABLE: Shell command injection
    cmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s", userInput))
    return cmd.Run()
}

// 4. PATH TRAVERSAL
func readFile(filename string) ([]byte, error) {
    // VULNERABLE: No path validation
    filepath := fmt.Sprintf("./uploads/%s", filename)
    return ioutil.ReadFile(filepath)
}

// 5. WEAK CRYPTOGRAPHY
func hashPassword(password string) string {
    // VULNERABLE: Using MD5
    h := md5.New()
    h.Write([]byte(password))
    return fmt.Sprintf("%x", h.Sum(nil))
}

// 6. INSECURE RANDOMNESS
func generateToken() string {
    // VULNERABLE: Weak random generation
    rand.Seed(time.Now().Unix())
    return strconv.Itoa(rand.Int())
}

// 7. RACE CONDITION
var globalCounter int

func incrementCounter() {
    // VULNERABLE: No synchronization
    temp := globalCounter
    time.Sleep(1 * time.Millisecond) // Simulate work
    globalCounter = temp + 1
}

// 8. MEMORY SAFETY ISSUES
func unsafeMemoryAccess() {
    // VULNERABLE: Unsafe pointer operations
    var x int = 42
    ptr := unsafe.Pointer(&x)
    
    // Dangerous pointer arithmetic
    newPtr := unsafe.Pointer(uintptr(ptr) + 8)
    y := (*int)(newPtr)
    *y = 100 // Could corrupt memory
}

// 9. SLICE BOUNDS VIOLATION
func accessSlice(index int) int {
    slice := make([]int, 10)
    // VULNERABLE: No bounds checking
    return slice[index]
}

// 10. MAP RACE CONDITION
var sharedMap = make(map[string]int)

func writeToMap(key string, value int) {
    // VULNERABLE: Concurrent map writes without sync
    sharedMap[key] = value
}

// 11. XSS VULNERABILITY
func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    
    // VULNERABLE: Direct HTML output without escaping
    html := fmt.Sprintf("<h1>Search results for: %s</h1>", query)
    w.Write([]byte(html))
}

// 12. TEMPLATE INJECTION
func templateHandler(w http.ResponseWriter, r *http.Request) {
    userTemplate := r.URL.Query().Get("template")
    
    // VULNERABLE: User-controlled template
    tmpl, err := template.New("user").Parse(userTemplate)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    tmpl.Execute(w, nil)
}

// 13. INFORMATION DISCLOSURE
func debugHandler(w http.ResponseWriter, r *http.Request) {
    // VULNERABLE: Exposing sensitive information
    debug := map[string]interface{}{
        "api_key":     APIKey,
        "db_password": DBPassword,
        "environment": os.Environ(),
        "request":     r,
    }
    
    fmt.Fprintf(w, "%+v", debug)
}

// 14. AUTHENTICATION BYPASS
func authenticate(username, password string) bool {
    // VULNERABLE: Logic flaw
    if username == "admin" || len(password) > 5 {
        return true
    }
    return false
}

// 15. TIMING ATTACK
func compareSecrets(userSecret, actualSecret string) bool {
    // VULNERABLE: Early return reveals timing
    for i := 0; i < len(actualSecret); i++ {
        if i >= len(userSecret) || userSecret[i] != actualSecret[i] {
            return false
        }
    }
    return len(userSecret) == len(actualSecret)
}

// 16. GOROUTINE LEAK
func leakGoroutines() {
    for i := 0; i < 1000; i++ {
        go func() {
            // VULNERABLE: Goroutines that never exit
            select {} // Block forever
        }()
    }
}

// 17. CHANNEL DEADLOCK
func deadlockExample() {
    ch := make(chan int)
    
    // VULNERABLE: Deadlock - no receiver
    ch <- 42
}

// 18. PANIC IN GOROUTINE
func panicInGoroutine() {
    go func() {
        // VULNERABLE: Unhandled panic in goroutine
        panic("Something went wrong")
    }()
}

// 19. RESOURCE LEAK
func resourceLeak() error {
    file, err := os.Open("test.txt")
    if err != nil {
        return err
    }
    
    // VULNERABLE: File not closed on all paths
    data := make([]byte, 100)
    if _, err := file.Read(data); err != nil {
        return err // File not closed!
    }
    
    file.Close()
    return nil
}

// 20. INSECURE DESERIALIZATION
func deserializeData(data string) interface{} {
    // VULNERABLE: Using eval-like functionality
    // This is a simplified example
    if strings.Contains(data, "admin") {
        return "admin_access"
    }
    return "user_access"
}

// 21. OPEN REDIRECT
func redirectHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("redirect")
    
    // VULNERABLE: No URL validation
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// 22. CSRF VULNERABILITY
func transferHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        return
    }
    
    from := r.FormValue("from")
    to := r.FormValue("to")
    amount := r.FormValue("amount")
    
    // VULNERABLE: No CSRF token validation
    log.Printf("Transfer %s from %s to %s", amount, from, to)
}

// 23. WEAK SESSION MANAGEMENT
func createSession(userID string) string {
    // VULNERABLE: Predictable session IDs
    return fmt.Sprintf("session_%s_%d", userID, time.Now().Unix())
}

// 24. BUFFER OVERFLOW SIMULATION
func bufferOverflow(input []byte) {
    buffer := make([]byte, 100)
    
    // VULNERABLE: No length checking
    copy(buffer, input) // Could overflow if input > 100 bytes
}

// 25. INTEGER OVERFLOW
func addNumbers(a, b int) int {
    // VULNERABLE: No overflow checking
    return a + b
}

// HTTP Server setup
func main() {
    // VULNERABLE: Server configuration issues
    http.HandleFunc("/search", searchHandler)
    http.HandleFunc("/template", templateHandler)
    http.HandleFunc("/debug", debugHandler)
    http.HandleFunc("/redirect", redirectHandler)
    http.HandleFunc("/transfer", transferHandler)
    
    // VULNERABLE: No timeouts, exposed to all interfaces
    server := &http.Server{
        Addr: ":8080",
        // No timeouts set
    }
    
    log.Println("Starting vulnerable server on :8080")
    log.Fatal(server.ListenAndServe())
}