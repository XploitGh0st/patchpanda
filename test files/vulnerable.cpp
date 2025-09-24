/* Vulnerable C++ Test Code for Patch Panda */
/* DO NOT USE IN PRODUCTION! */

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <memory>

// 1. HARDCODED SECRETS
const char* API_KEY = "sk-cpp123456789";
const char* DB_PASSWORD = "admin1234";

class VulnerableCode {
private:
    char buffer[100];
    int sensitive_data;

public:
    // 2. BUFFER OVERFLOW
    void copyString(const char* input) {
        // VULNERABLE: No bounds checking
        strcpy(buffer, input);
    }

    // 3. FORMAT STRING VULNERABILITY
    void logMessage(const char* user_input) {
        // VULNERABLE: Direct printf with user input
        printf(user_input);
    }

    // 4. USE AFTER FREE
    void useAfterFree() {
        char* ptr = new char[100];
        delete ptr;
        
        // VULNERABLE: Using freed memory
        strcpy(ptr, "dangerous");
        std::cout << ptr << std::endl;
    }

    // 5. DOUBLE FREE
    void doubleFree() {
        char* ptr = new char[100];
        delete ptr;
        // VULNERABLE: Double free
        delete ptr;
    }

    // 6. MEMORY LEAK
    void memoryLeak() {
        for (int i = 0; i < 1000; i++) {
            // VULNERABLE: No delete, causes memory leak
            char* leak = new char[1000];
        }
    }

    // 7. NULL POINTER DEREFERENCE
    void nullPointerDeref(char* ptr) {
        // VULNERABLE: No null check
        *ptr = 'A';
    }

    // 8. INTEGER OVERFLOW
    int addNumbers(int a, int b) {
        // VULNERABLE: No overflow checking
        return a + b;
    }

    // 9. ARRAY BOUNDS VIOLATION
    void accessArray(int index) {
        int arr[10];
        // VULNERABLE: No bounds checking
        arr[index] = 42;
    }

    // 10. RACE CONDITION
    static int shared_counter;
    void incrementCounter() {
        // VULNERABLE: No synchronization
        shared_counter++;
    }

    // 11. COMMAND INJECTION
    void executeCommand(const std::string& user_input) {
        std::string command = "ls " + user_input;
        // VULNERABLE: Direct system call
        system(command.c_str());
    }

    // 12. PATH TRAVERSAL
    std::string readFile(const std::string& filename) {
        // VULNERABLE: No path validation
        std::string filepath = "./files/" + filename;
        std::ifstream file(filepath);
        
        std::string content;
        std::string line;
        while (std::getline(file, line)) {
            content += line;
        }
        return content;
    }

    // 13. WEAK RANDOM NUMBER GENERATION
    int generateRandomNumber() {
        // VULNERABLE: Using weak rand()
        return rand();
    }

    // 14. INFORMATION DISCLOSURE
    void printSensitiveInfo() {
        // VULNERABLE: Exposing sensitive data
        std::cout << "API Key: " << API_KEY << std::endl;
        std::cout << "DB Password: " << DB_PASSWORD << std::endl;
        std::cout << "Memory address: " << &sensitive_data << std::endl;
    }

    // 15. UNCHECKED RETURN VALUE
    void writeToFile(const std::string& data) {
        FILE* file = fopen("output.txt", "w");
        // VULNERABLE: Not checking if fopen succeeded
        fprintf(file, "%s", data.c_str());
        fclose(file);
    }

    // 16. STACK BUFFER OVERFLOW
    void stackOverflow(const char* input) {
        char local_buffer[50];
        // VULNERABLE: No size checking
        strcpy(local_buffer, input);
    }

    // 17. HEAP BUFFER OVERFLOW
    void heapOverflow(const char* input, size_t size) {
        char* heap_buffer = new char[100];
        // VULNERABLE: No bounds checking
        memcpy(heap_buffer, input, size);
        delete[] heap_buffer;
    }

    // 18. UNINITIALIZED VARIABLE
    int getRandomValue() {
        int uninitialized;
        // VULNERABLE: Using uninitialized variable
        return uninitialized;
    }

    // 19. DANGLING POINTER
    char* getDanglingPointer() {
        char local_array[100] = "test";
        // VULNERABLE: Returning pointer to local variable
        return local_array;
    }

    // 20. IMPROPER INPUT VALIDATION
    void processInput(const char* input) {
        // VULNERABLE: No input validation
        int value = atoi(input);
        char result[10];
        sprintf(result, "%d", value);
    }
};

// Initialize static member
int VulnerableCode::shared_counter = 0;

// 21. UNSAFE FUNCTION USAGE
void unsafeFunctions() {
    char buffer[100];
    
    // VULNERABLE: Using unsafe functions
    gets(buffer);           // Buffer overflow risk
    sprintf(buffer, "%s");  // Format string vulnerability
    strcat(buffer, "test"); // Potential buffer overflow
}

// 22. WEAK CRYPTOGRAPHY IMPLEMENTATION
void weakCrypto(const char* password) {
    // VULNERABLE: Weak encryption
    for (int i = 0; i < strlen(password); i++) {
        printf("%c", password[i] ^ 0x42);  // XOR with constant
    }
}

// 23. TIME-OF-CHECK TIME-OF-USE (TOCTOU)
void tocttouVulnerability(const char* filename) {
    // VULNERABLE: Race condition between check and use
    if (access(filename, F_OK) == 0) {
        // File exists, but could be deleted/modified here
        FILE* file = fopen(filename, "r");
        // Use file...
        fclose(file);
    }
}

// 24. STACK EXHAUSTION
void stackExhaustion(int depth) {
    char large_array[10000];
    // VULNERABLE: Recursive calls without limit
    if (depth > 0) {
        stackExhaustion(depth - 1);
    }
}

// 25. IMPROPER RESOURCE CLEANUP
void resourceLeak() {
    FILE* file = fopen("test.txt", "r");
    char buffer[100];
    
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        // VULNERABLE: File not closed on error path
        return;
    }
    
    fclose(file);
}

int main() {
    VulnerableCode vc;
    
    // Example calls that would trigger vulnerabilities
    vc.copyString("This is a very long string that will overflow the buffer and cause a security vulnerability");
    vc.logMessage("%s%s%s%s");  // Format string attack
    vc.useAfterFree();
    vc.nullPointerDeref(nullptr);
    
    std::cout << "Vulnerable C++ code executed" << std::endl;
    
    return 0;
}