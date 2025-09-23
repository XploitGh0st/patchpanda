// Vulnerable Java Test Code for Patch Panda
// DO NOT USE IN PRODUCTION!

import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Random;
import javax.servlet.http.*;
import java.lang.Runtime;

public class VulnerableCode {
    
    // 1. HARDCODED SECRETS
    private static final String API_KEY = "sk-java123456789";
    private static final String DB_PASSWORD = "admin123";
    private static final String ENCRYPTION_KEY = "mySecretKey2024";
    
    // 2. SQL INJECTION
    public ResultSet getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/myapp", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        
        // VULNERABLE: String concatenation in SQL
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }
    
    // 3. COMMAND INJECTION
    public void executeCommand(String userInput) {
        try {
            // VULNERABLE: Direct command execution
            Runtime.getRuntime().exec("cmd /c dir " + userInput);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // 4. PATH TRAVERSAL
    public String readFile(String filename) {
        try {
            // VULNERABLE: No path validation
            FileReader file = new FileReader("uploads/" + filename);
            BufferedReader reader = new BufferedReader(file);
            return reader.readLine();
        } catch (IOException e) {
            return "Error reading file";
        }
    }
    
    // 5. WEAK CRYPTOGRAPHY
    public String hashPassword(String password) {
        try {
            // VULNERABLE: Using MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return new String(hash);
        } catch (Exception e) {
            return null;
        }
    }
    
    // 6. INSECURE RANDOMNESS
    public String generateSessionId() {
        Random random = new Random();
        // VULNERABLE: Predictable random numbers
        return String.valueOf(random.nextInt(10000));
    }
    
    // 7. DESERIALIZATION
    public Object deserializeData(byte[] data) {
        try {
            // VULNERABLE: Unsafe deserialization
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            return ois.readObject();
        } catch (Exception e) {
            return null;
        }
    }
    
    // 8. XSS VULNERABILITY (in JSP context)
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userInput = request.getParameter("input");
            PrintWriter out = response.getWriter();
            
            // VULNERABLE: Direct output without encoding
            out.println("<h1>Hello " + userInput + "</h1>");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // 9. INFORMATION DISCLOSURE
    public void logSensitiveData(String username, String password, String ssn) {
        // VULNERABLE: Logging sensitive information
        System.out.println("User: " + username + ", Pass: " + password + ", SSN: " + ssn);
    }
    
    // 10. RACE CONDITION
    private int counter = 0;
    
    public void incrementCounter() {
        // VULNERABLE: No synchronization
        int temp = counter;
        temp++;
        counter = temp;
    }
    
    // 11. BUFFER OVERFLOW SIMULATION
    public void processArray(int[] input) {
        int[] buffer = new int[10];
        
        // VULNERABLE: No bounds checking
        for (int i = 0; i < input.length; i++) {
            buffer[i] = input[i];
        }
    }
    
    // 12. LDAP INJECTION
    public void searchLDAP(String username) {
        try {
            // VULNERABLE: String concatenation in LDAP filter
            String filter = "(uid=" + username + ")";
            System.out.println("LDAP Filter: " + filter);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 13. XML EXTERNAL ENTITY (XXE)
    public void parseXML(String xmlData) {
        try {
            // VULNERABLE: No XXE protection
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            
            org.w3c.dom.Document doc = builder.parse(
                new java.io.ByteArrayInputStream(xmlData.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 14. TIMING ATTACK
    public boolean compareSecrets(String userSecret, String actualSecret) {
        // VULNERABLE: Early return reveals timing information
        for (int i = 0; i < actualSecret.length(); i++) {
            if (i >= userSecret.length() || userSecret.charAt(i) != actualSecret.charAt(i)) {
                return false;
            }
        }
        return userSecret.length() == actualSecret.length();
    }
    
    // 15. INSECURE DIRECT OBJECT REFERENCE
    public String getUserProfile(String userId) {
        // VULNERABLE: No authorization check
        try {
            ResultSet rs = getUserData(userId);
            if (rs.next()) {
                return rs.getString("profile");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}