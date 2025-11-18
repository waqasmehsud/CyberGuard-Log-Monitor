#include <iostream>
#include <string>
#include <ctime>
using namespace std;

// SINGLY LINKED LIST: LOG STREAM BUFFER
struct LogNode {
    string message;
    LogNode* next;
    
    LogNode(string msg) : message(msg), next(NULL) {}
};

class LogStream {
private:
    LogNode* head;
    int count;
    const int MAX_LOGS = 10;
    
public:
    LogStream() : head(NULL), count(0) {}
    
    void AppendLog(string message) {
        LogNode* newNode = new LogNode(message);
        
        if (head == NULL) {
            head = newNode;
        } else {
            LogNode* temp = head;
            while (temp->next != NULL) {
                temp = temp->next;
            }
            temp->next = newNode;
        }
        count++;
        
        if (count > MAX_LOGS) {
            DeleteOldest();
        }
    }
    
    void DeleteOldest() {
        if (head == NULL) return;
        
        LogNode* temp = head;
        head = head->next;
        delete temp;
        count--;
    }
    
    void DeleteLog(string keyword) {
        if (head == NULL) return;
        
        if (head->message.find(keyword) != string::npos) {
            LogNode* temp = head;
            head = head->next;
            delete temp;
            count--;
            cout << "Deleted log containing: " << keyword << endl;
            return;
        }
        
        LogNode* current = head;
        while (current->next != NULL) {
            if (current->next->message.find(keyword) != string::npos) {
                LogNode* temp = current->next;
                current->next = current->next->next;
                delete temp;
                count--;
                cout << "Deleted log containing: " << keyword << endl;
                return;
            }
            current = current->next;
        }
        cout << "No log found with keyword: " << keyword << endl;
    }
    
    void DisplayLogs() {
        cout << "\n=== LOG STREAM BUFFER (" << count << " logs) ===" << endl;
        if (head == NULL) {
            cout << "No logs available." << endl;
            return;
        }
        
        LogNode* temp = head;
        int index = 1;
        while (temp != NULL) {
            cout << index++ << ". " << temp->message << endl;
            temp = temp->next;
        }
    }
    
    bool ContainsSuspiciousKeyword(string message) {
        string keywords[] = {"failed", "scan", "malware", "breach", "unauthorized"};
        for (int i = 0; i < 5; i++) {
            if (message.find(keywords[i]) != string::npos) {
                return true;
            }
        }
        return false;
    }
    
    ~LogStream() {
        while (head != NULL) {
            LogNode* temp = head;
            head = head->next;
            delete temp;
        }
    }
};

// DOUBLY LINKED LIST: SUSPICIOUS EVENT TIMELINE
struct EventNode {
    string timestamp;
    string severity;
    string message;
    EventNode* next;
    EventNode* prev;
    
    EventNode(string ts, string sev, string msg) 
        : timestamp(ts), severity(sev), message(msg), next(NULL), prev(NULL) {}
};

class EventTimeline {
private:
    EventNode* head;
    EventNode* tail;
    
    string DetermineSeverity(string message) {
        if (message.find("malware") != string::npos || 
            message.find("breach") != string::npos) {
            return "High";
        } else if (message.find("scan") != string::npos || 
                   message.find("unauthorized") != string::npos) {
            return "Med";
        } else {
            return "Low";
        }
    }
    
    string GetTimestamp() {
        time_t now = time(0);
        string dt = ctime(&now);
        dt.pop_back();
        return dt;
    }
    
public:
    EventTimeline() : head(NULL), tail(NULL) {}
    
    void InsertEventAtFront(string message) {
        string timestamp = GetTimestamp();
        string severity = DetermineSeverity(message);
        EventNode* newNode = new EventNode(timestamp, severity, message);
        
        if (head == NULL) {
            head = tail = newNode;
        } else {
            newNode->next = head;
            head->prev = newNode;
            head = newNode;
        }
    }
    
    void DeleteEventAtEnd() {
        if (tail == NULL) {
            cout << "No events to delete." << endl;
            return;
        }
        
        if (head == tail) {
            delete tail;
            head = tail = NULL;
        } else {
            EventNode* temp = tail;
            tail = tail->prev;
            tail->next = NULL;
            delete temp;
        }
        cout << "Oldest event deleted." << endl;
    }
    
    void ForwardTraversal() {
        cout << "\n=== SUSPICIOUS EVENTS (Latest to Oldest) ===" << endl;
        if (head == NULL) {
            cout << "No suspicious events." << endl;
            return;
        }
        
        EventNode* temp = head;
        int index = 1;
        while (temp != NULL) {
            cout << index++ << ". [" << temp->severity << "] " 
                 << temp->timestamp << " - " << temp->message << endl;
            temp = temp->next;
        }
    }
    
    void BackwardTraversal() {
        cout << "\n=== SUSPICIOUS EVENTS (Oldest to Latest) ===" << endl;
        if (tail == NULL) {
            cout << "No suspicious events." << endl;
            return;
        }
        
        EventNode* temp = tail;
        int index = 1;
        while (temp != NULL) {
            cout << index++ << ". [" << temp->severity << "] " 
                 << temp->timestamp << " - " << temp->message << endl;
            temp = temp->prev;
        }
    }
    
    ~EventTimeline() {
        while (head != NULL) {
            EventNode* temp = head;
            head = head->next;
            delete temp;
        }
    }
};

// CIRCULAR LINKED LIST: ALERT HANDLER ROTATION
struct HandlerNode {
    string name;
    HandlerNode* next;
    
    HandlerNode(string n) : name(n), next(NULL) {}
};

class HandlerRotation {
private:
    HandlerNode* current;
    int count;
    
public:
    HandlerRotation() : current(NULL), count(0) {}
    
    void AddHandler(string name) {
        HandlerNode* newNode = new HandlerNode(name);
        
        if (current == NULL) {
            current = newNode;
            current->next = current;
        } else {
            HandlerNode* temp = current;
            while (temp->next != current) {
                temp = temp->next;
            }
            temp->next = newNode;
            newNode->next = current;
        }
        count++;
    }
    
    void RemoveHandler(string name) {
        if (current == NULL) {
            cout << "No handlers to remove." << endl;
            return;
        }
        
        HandlerNode* temp = current;
        HandlerNode* prev = NULL;
        
        do {
            if (temp->name == name) {
                if (temp == current && temp->next == current) {
                    delete current;
                    current = NULL;
                    count--;
                    cout << "Handler " << name << " removed." << endl;
                    return;
                }
                
                HandlerNode* toDelete = temp;
                prev = current;
                while (prev->next != temp) {
                    prev = prev->next;
                }
                prev->next = temp->next;
                
                if (temp == current) {
                    current = temp->next;
                }
                
                delete toDelete;
                count--;
                cout << "Handler " << name << " removed." << endl;
                return;
            }
            prev = temp;
            temp = temp->next;
        } while (temp != current);
        
        cout << "Handler " << name << " not found." << endl;
    }
    
    string NextHandler() {
        if (current == NULL) return "No handler available";
        
        string handler = current->name;
        current = current->next;
        return handler;
    }
    
    void DisplayHandlers() {
        cout << "\n=== ALERT HANDLER ROTATION ===" << endl;
        if (current == NULL) {
            cout << "No handlers available." << endl;
            return;
        }
        
        HandlerNode* temp = current;
        cout << "Handlers in rotation: ";
        do {
            cout << temp->name;
            temp = temp->next;
            if (temp != current) cout << " -> ";
        } while (temp != current);
        cout << " -> (cycles back)" << endl;
        cout << "Current handler: " << current->name << endl;
    }
    
    ~HandlerRotation() {
        if (current == NULL) return;
        
        HandlerNode* temp = current->next;
        while (temp != current) {
            HandlerNode* next = temp->next;
            delete temp;
            temp = next;
        }
        delete current;
    }
};

// MAIN APPLICATION
void DisplayMenu() {
    cout << "\n--------------------------------------------------" << endl;
    cout << "       CYBERGUARD LOG-MONITORING SYSTEM        " << endl;
    cout << "--------------------------------------------------" << endl;
    cout << "  LOG STREAM OPERATIONS:                     " << endl;
    cout << "    1. Add New Log Entry                     " << endl;
    cout << "    2. Delete Log by Keyword                 " << endl;
    cout << "    3. Display All Logs                      " << endl;
    cout << "                                             " << endl;
    cout << "  SUSPICIOUS EVENT OPERATIONS:               " << endl;
    cout << "    4. Display Events (Latest to Oldest)     " << endl;
    cout << "    5. Display Events (Oldest to Latest)     " << endl;
    cout << "    6. Delete Oldest Suspicious Event        " << endl;
    cout << "                                             " << endl;
    cout << "  ALERT HANDLER OPERATIONS:                  " << endl;
    cout << "    7. Add Alert Handler                     " << endl;
    cout << "    8. Remove Alert Handler                  " << endl;
    cout << "    9. Display Handler Rotation              " << endl;
    cout << "                                             " << endl;
    cout << "  DEMONSTRATION:                             " << endl;
    cout << "   10. Run Auto Demo (15 Sample Logs)        " << endl;
    cout << "                                             " << endl;
    cout << "    0. Exit System                           " << endl;
    cout << "--------------------------------------------------" << endl;
    cout << "Enter your choice: ";
}

int main() {
    LogStream logStream;
    EventTimeline eventTimeline;
    HandlerRotation handlerRotation;
    
    cout << "\n--------------------------------------------------" << endl;
    cout << "                                              " << endl;
    cout << "     CYBERGUARD LOG-MONITORING SYSTEM        " << endl;
    cout << "        Security Operations Center            " << endl;
    cout << "                                              " << endl;
    cout << "--------------------------------------------------" << endl;
    
    cout << "\n[*] Initializing Alert Handlers..." << endl;
    handlerRotation.AddHandler("Handler-A");
    handlerRotation.AddHandler("Handler-B");
    handlerRotation.AddHandler("Handler-C");
    cout << "[OK] System Ready!" << endl;
    
    int choice;
    string input, keyword, handlerName;
    
    while (true) {
        DisplayMenu();
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
            case 1:
                cout << "\n--- ADD NEW LOG ENTRY ---" << endl;
                cout << "Enter log message: ";
                getline(cin, input);
                logStream.AppendLog(input);
                cout << "[Ok] Log added successfully!" << endl;
                
                if (logStream.ContainsSuspiciousKeyword(input)) {
                    cout << "\n[!] SUSPICIOUS ACTIVITY DETECTED!" << endl;
                    eventTimeline.InsertEventAtFront(input);
                    string handler = handlerRotation.NextHandler();
                    cout << "[@] Event assigned to: " << handler << endl;
                }
                break;
                
            case 2:
                cout << "\n--- DELETE LOG BY KEYWORD ---" << endl;
                cout << "Enter keyword to search: ";
                getline(cin, keyword);
                logStream.DeleteLog(keyword);
                break;
                
            case 3:
                logStream.DisplayLogs();
                break;
                
            case 4:
                eventTimeline.ForwardTraversal();
                break;
                
            case 5:
                eventTimeline.BackwardTraversal();
                break;
                
            case 6:
                cout << "\n--- DELETE OLDEST EVENT ---" << endl;
                eventTimeline.DeleteEventAtEnd();
                break;
                
            case 7:
                cout << "\n--- ADD ALERT HANDLER ---" << endl;
                cout << "Enter handler name: ";
                getline(cin, handlerName);
                handlerRotation.AddHandler(handlerName);
                cout << "[OK] Handler added successfully!" << endl;
                break;
                
            case 8:
                cout << "\n--- REMOVE ALERT HANDLER ---" << endl;
                cout << "Enter handler name: ";
                getline(cin, handlerName);
                handlerRotation.RemoveHandler(handlerName);
                break;
                
            case 9:
                handlerRotation.DisplayHandlers();
                break;
                
            case 10: {
                cout << "\n--------------------------------------------------" << endl;
                cout << "       RUNNING AUTOMATED DEMONSTRATION       " << endl;
                cout << "--------------------------------------------------" << endl;
                
                string logs[] = {
                    "Login successful from IP 192.168.1.10",
                    "Login failed from IP 203.45.67.89",
                    "Port scan detected from IP 45.76.123.45",
                    "File integrity verified for system.dll",
                    "Malware signature detected in download.exe",
                    "Unauthorized access attempt on database",
                    "System backup completed successfully",
                    "Login failed from IP 198.51.100.42",
                    "Network traffic normal",
                    "Breach attempt blocked on firewall",
                    "User authentication successful",
                    "Failed SSH connection from IP 10.0.0.15",
                    "File integrity change detected in config.sys",
                    "System update installed",
                    "Port scan detected from IP 172.16.0.99"
                };
                
                cout << "\n[*] Processing 15 sample log entries...\n" << endl;
                
                for (int i = 0; i < 15; i++) {
                    cout << "----------------------------------------------" << endl;
                    cout << "Log #" << (i + 1) << ": " << logs[i] << endl;
                    
                    logStream.AppendLog(logs[i]);
                    
                    if (logStream.ContainsSuspiciousKeyword(logs[i])) {
                        cout << "[!] SUSPICIOUS ACTIVITY DETECTED!" << endl;
                        eventTimeline.InsertEventAtFront(logs[i]);
                        string handler = handlerRotation.NextHandler();
                        cout << "[@] Assigned to: " << handler << endl;
                    }
                }
                
                cout << "\n[OK] Demo completed!" << endl;
                logStream.DisplayLogs();
                eventTimeline.ForwardTraversal();
                handlerRotation.DisplayHandlers();
                
                cout << "\n--- Additional Demonstrations ---" << endl;
                cout << "\n[*] Backward Traversal of Events:" << endl;
                eventTimeline.BackwardTraversal();
                
                cout << "\n[*] Deleting log containing 'backup':" << endl;
                logStream.DeleteLog("backup");
                
                cout << "\n[*] Deleting oldest suspicious event:" << endl;
                eventTimeline.DeleteEventAtEnd();
                
                cout << "\n[*] Removing Handler-B:" << endl;
                handlerRotation.RemoveHandler("Handler-B");
                handlerRotation.DisplayHandlers();
                
                cout << "\n[DONE] All demonstrations complete!" << endl;
                break;
            }
                
            case 0:
                cout << "\n--------------------------------------------------" << endl;
                cout << "   Shutting down CyberGuard System...        " << endl;
                cout << "          Stay secure! Goodbye!              " << endl;
                cout << "--------------------------------------------------\n" << endl;
                return 0;
                
            default:
                cout << "\n[!] Invalid choice! Please select 0-10." << endl;
        }
        
        cout << "\nPress Enter to continue...";
        cin.get();
    }
    
    return 0;
}