# CyberGuard Log-Monitoring System

**CyberGuard** is a C++ console-based simulation of a Security Operations Center (SOC) log monitoring system. It utilizes three distinct types of Linked Lists to manage security logs, track suspicious event timelines, and rotate alert handlers efficiently.

## 🚀 Project Overview

This project demonstrates the practical application of Data Structures in a cybersecurity context:

1.  **Log Buffer (Singly Linked List):** Stores incoming raw logs. Automatically deletes the oldest logs when the buffer limit (10) is reached.
2.  **Event Timeline (Doubly Linked List):** Tracks suspicious events with severity levels (High, Med, Low). Allows traversal from latest-to-oldest and oldest-to-latest.
3.  **Handler Rotation (Circular Linked List):** Manages a team of security handlers in a round-robin fashion to assign incoming threats.

## 🛠️ Tech Stack

* **Language:** C++ (Standard 11+)
* **Concepts:** OOP, Pointers, Dynamic Memory Management
* **Data Structures:**
    * Singly Linked List
    * Doubly Linked List
    * Circular Linked List

## ⚙️ Features

* **Real-time Log Ingestion:** Add logs dynamically with timestamp generation.
* **Keyword Detection:** Automatically scans for keywords like "malware", "breach", and "scan".
* **Severity tagging:** Classifies threats as High, Medium, or Low based on context.
* **Automated Demo:** Includes a built-in demonstration mode processing 15 simulated cyber events.

## 💻 How to Run

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR-USERNAME/CyberGuard-Log-Monitor.git](https://github.com/YOUR-USERNAME/CyberGuard-Log-Monitor.git)
    ```
2.  **Compile the code:**
    ```bash
    g++ main.cpp -o cyberguard
    ```
3.  **Run the executable:**
    * Windows: `cyberguard.exe`
    * Linux/Mac: `./cyberguard`

## 📂 Project Structure

```text
├── main.cpp       # Source code containing all Linked List implementations
└── README.md      # Project documentation