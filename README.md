# 🚨 Splunk → n8n → Discord

## SOC Incident Automation for SSH Brute Force Detection (auth.log)

---

## 🔍 Project Overview

This project implements a **SOC-style security automation pipeline** that detects **SSH brute-force attacks** using **Linux authentication logs (`auth.log`)** and sends **real-time incident alerts** to a **Discord SOC channel**.

> 🛡️ **Linux auth.log → Splunk (SIEM) → n8n (SOAR) → Discord (#incident)**

When repeated SSH login failures are detected, Splunk triggers an alert and sends structured data to **n8n**, where the event is **classified by severity** and forwarded to Discord as a **formatted incident notification**.

This project demonstrates **real-world SOC alerting, triage, and SOAR automation** without using IDS tools like Suricata.

---

## 🎯 Objectives

* Detect SSH brute-force attacks from Linux systems
* Reduce alert noise using aggregation and throttling
* Automatically classify incidents by severity
* Deliver clean, real-time SOC notifications
* Demonstrate SIEM + SOAR integration

---

## 🧩 Key Features

### ✔ SSH Brute Force Detection (auth.log)

* Parses `/var/log/auth.log`
* Detects repeated `Failed password` events
* Aggregates attempts per attacker IP

---

### ✔ Severity-Based Classification (n8n)

| Failed Attempts | Severity | SOC Action         |
| --------------- | -------- | ------------------ |
| < 5             | NORMAL   | Log only           |
| 5–10            | MEDIUM   | Monitor            |
| > 15            | RISK     | Immediate response |

---

### ✔ Discord-Based SOC Alerts

* Alerts sent as **Discord embeds**
* Clear severity indicators (🟢🟠🔴)
* Clickable Splunk evidence links
* Prevents alert fatigue

---

### ✔ SOAR-Ready Design

The workflow can be extended with:

* IP reputation checks
* Auto-blocking via firewall
* Incident ticket creation
* Correlation with IDS tools (future)

---

## 🧱 Architecture

```
[ Linux auth.log ]
        ↓
     [ Splunk ]
 (SSH Brute Force SPL)
        ↓
     [ Webhook ]
        ↓
       [ n8n ]
 (Severity Evaluation)
        ↓
     [ Discord ]
   (#incident channel)
```

---

## 📸 Outputs:

<img width="1486" height="478" alt="2025-12-17_19-27" src="https://github.com/user-attachments/assets/08a95236-1ba4-4fdf-9fb1-2c20bf2b8983" />

<img width="1768" height="753" alt="2025-12-17_19-21" src="https://github.com/user-attachments/assets/3b2ca530-d81e-4dcb-8b37-ce7a5bed5a6b" />

<img width="1090" height="869" alt="2025-12-17_19-29" src="https://github.com/user-attachments/assets/80ea307e-e93d-4093-ba10-3cd5b1ffcda9" />

<img width="779" height="774" alt="2025-12-17_21-02" src="https://github.com/user-attachments/assets/5fc2af45-4d6b-4b91-ac39-4a33448d6b88" />


---

## ⚙️ Workflow Summary

| Step | Component       | Description                  |
| ---- | --------------- | ---------------------------- |
| 1️⃣  | Linux auth.log  | Generates SSH failures       |
| 2️⃣  | Splunk SPL      | Detects brute-force behavior |
| 3️⃣  | Splunk Alert    | Triggers webhook             |
| 4️⃣  | n8n Webhook     | Receives alert payload       |
| 5️⃣  | n8n Logic       | Classifies severity          |
| 6️⃣  | Discord Webhook | Sends incident alert         |

---

# ⚙️ Setup Guide

---

## 1️⃣ Splunk – SSH Brute Force Detection

### SPL Query

```spl
index=* source="/var/log/auth.log" "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count AS attempts by src_ip
| eval severity=case(
    attempts >= 15, "RISK",
    attempts >= 5, "MEDIUM"
)
```

**What this does:**

* Extracts attacker IP addresses
* Counts failed login attempts
* Flags suspicious behavior

---

## 2️⃣ Splunk Alert Configuration

* **Alert type:** Scheduled
* **Run every:** 1 minute
* **Time range:** Last 5 minutes
* **Trigger when:** Number of results > 0
* **Trigger mode:** For each result
* **Throttle:** 120 seconds by `src_ip`

### Webhook Action

```
POST http://<n8n-ip>:5678/webhook/ssh
```

---

## 3️⃣ n8n Workflow – Node-by-Node Details

---

### 🧩 Node 1: Webhook (Receive Splunk Alert)

* **Method:** POST
* **Path:** `/webhook/ssh`
* **Authentication:** None (internal network)

#### Example Payload from Splunk

```json
{
  "result": {
    "src_ip": "192.168.122.1",
    "count": "44"
  },
  "search_name": "SSH Brute Force Detection",
  "results_link": "http://splunk:8000/app/search/search?q=..."
}
```

---

### 🧩 Node 2: Edit Fields (Normalize Data)

| Field       | Expression                |
| ----------- | ------------------------- |
| attacker_ip | `{{$json.result.src_ip}}` |
| attempts    | `{{$json.result.count}}`  |
| splunk_link | `{{$json.results_link}}`  |
| search_name | `{{$json.search_name}}`   |

---

### 🧩 Node 3: Code Node (Severity Evaluation)

```js
const attempts = parseInt($json.attempts);

let severity = "NORMAL";
let action = "Log activity only.";

if (attempts >= 5 && attempts <= 10) {
  severity = "MEDIUM";
  action = "Monitor suspicious activity.";
}

if (attempts > 15) {
  severity = "RISK";
  action = "Immediate investigation required.";
}

return [{
  json: {
    attacker_ip: $json.attacker_ip,
    attempts,
    severity,
    action,
    splunk_link: $json.splunk_link,
    search_name: $json.search_name
  }
}];
```

---

### 🧩 Node 4: IF Node – RISK

**Condition**

```
{{$json.severity}} is equal to RISK
```

* TRUE → Discord (HIGH RISK)
* FALSE → Next IF node

---

### 🧩 Node 5: IF Node – MEDIUM

**Condition**

```
{{$json.severity}} is equal to MEDIUM
```

* TRUE → Discord (MEDIUM)
* FALSE → Discord (NORMAL)

---

## 🧩 Discord Webhook Templates

---

### 🔴 HIGH RISK

```json
{
  "username": "SOC Incident Manager",
  "embeds": [
    {
      "title": "🔴 SSH BRUTE FORCE – HIGH RISK",
      "color": 15158332,
      "fields": [
        { "name": "Attacker IP", "value": "{{$json.attacker_ip}}", "inline": true },
        { "name": "Attempts", "value": "{{$json.attempts}}", "inline": true },
        { "name": "Severity", "value": "RISK", "inline": true },
        { "name": "Action Required", "value": "{{$json.action}}", "inline": false },
        { "name": "Splunk Evidence", "value": "[View]({{$json.splunk_link}})", "inline": false }
      ],
      "footer": { "text": "SOC Automation | Immediate Response Required" }
    }
  ]
}
```

---

### 🟠 MEDIUM

```json
{
  "username": "SOC Incident Manager",
  "embeds": [
    {
      "title": "🟠 SUSPICIOUS SSH ACTIVITY",
      "color": 16753920,
      "fields": [
        { "name": "Attacker IP", "value": "{{$json.attacker_ip}}", "inline": true },
        { "name": "Attempts", "value": "{{$json.attempts}}", "inline": true },
        { "name": "Severity", "value": "MEDIUM", "inline": true },
        { "name": "Action", "value": "{{$json.action}}", "inline": false },
        { "name": "Splunk Evidence", "value": "[View]({{$json.splunk_link}})", "inline": false }
      ],
      "footer": { "text": "SOC Automation | Monitoring" }
    }
  ]
}
```

---

### 🟢 NORMAL

```json
{
  "username": "SOC Incident Manager",
  "embeds": [
    {
      "title": "🟢 SSH ACTIVITY LOGGED",
      "color": 3066993,
      "fields": [
        { "name": "Attacker IP", "value": "{{$json.attacker_ip}}", "inline": true },
        { "name": "Attempts", "value": "{{$json.attempts}}", "inline": true },
        { "name": "Severity", "value": "NORMAL", "inline": true }
      ],
      "footer": { "text": "SOC Automation | Informational" }
    }
  ]
}
```

---

## 🧠 SOC Skills Demonstrated

* SIEM alert engineering (Splunk)
* Linux log analysis (`auth.log`)
* Brute-force detection logic
* SOAR automation with n8n
* Incident severity classification
* Webhook-based integrations

---
