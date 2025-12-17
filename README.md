# 🚨 Splunk + Suricata → n8n → Discord

## SOC Incident Automation for SSH Brute Force Detection

---

## 🔍 Project Overview

This project implements a **Security Operations Center (SOC) automation pipeline** that detects **SSH brute-force attacks** and generates **real-time incident notifications** in a **Discord SOC channel**.

> 🛡️ **Linux / Suricata Logs → Splunk (SIEM) → n8n (SOAR) → Discord (#incident)**

When repeated SSH authentication failures are detected, Splunk triggers an alert, sends structured data to **n8n**, where the event is **classified by severity** and forwarded to Discord as a **formatted incident notification**.

This project simulates **real-world SOC alerting and SOAR workflows** used by blue teams.

---

## 🎯 Objectives

* Detect SSH brute-force attacks
* Reduce alert noise using aggregation & throttling
* Automatically classify incidents by severity
* Deliver clean, real-time SOC alerts
* Demonstrate SIEM + SOAR integration

---

## 🧩 Key Features

### ✔ SSH Brute Force Detection (Splunk)

* Parses Linux authentication logs
* Extracts attacker IPs
* Counts failed login attempts per IP

### ✔ Severity-Based Classification (n8n)

| Failed Attempts | Severity | SOC Action         |
| --------------- | -------- | ------------------ |
| < 5             | NORMAL   | Log only           |
| 5–10            | MEDIUM   | Monitor            |
| > 15            | RISK     | Immediate response |

### ✔ Discord-Based SOC Alerts

* Alerts sent as **Discord embeds**
* Clear severity indicators (🟢🟠🔴)
* Clickable Splunk evidence links

### ✔ SOAR-Ready Architecture

Easily extendable with:

* IP reputation checks
* Auto-blocking
* Ticket creation (TheHive / Jira)
* Threat intelligence enrichment

---

## 🧱 Architecture

```
[ Linux / Suricata Logs ]
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

## 📸 Example Output (Discord)

🔴 **SSH BRUTE FORCE – HIGH RISK**

* Attacker IP: `192.168.122.1`
* Attempts: `44`
* Severity: **RISK**
* Action: Immediate investigation required
* Evidence: Clickable Splunk search link

---

## ⚙️ Workflow Summary

| Step | Component             | Description                 |
| ---- | --------------------- | --------------------------- |
| 1️⃣  | Linux / Suricata Logs | Generate SSH failures       |
| 2️⃣  | Splunk SPL            | Detect brute-force behavior |
| 3️⃣  | Splunk Alert          | Triggers webhook            |
| 4️⃣  | n8n Webhook           | Receives alert payload      |
| 5️⃣  | n8n Logic             | Classifies severity         |
| 6️⃣  | Discord Webhook       | Sends incident alert        |

---

# ⚙️ Setup Guide

---

## 1️⃣ Splunk – SSH Brute Force Detection

### SPL Query

```spl
index=* source="/var/log/auth.log" "Failed password"
earliest=-5m latest=now
| rex "from (?<src_ip>\d{1,3}(\.\d{1,3}){3})"
| stats count by src_ip
| where count >= 5
```

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

#### Example Incoming Payload

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

| Field       | Value                     |
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
    attempts: attempts,
    severity: severity,
    action: action,
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

## 🔐 Security Considerations

* Internal-only webhooks
* Alert throttling enabled
* No plaintext secrets
* Extensible authentication support

---

## 🚀 Future Enhancements

* IP reputation enrichment
* Auto-block attacker IPs
* Case lifecycle tracking
* Suricata + SSH correlation
* SOC dashboards
* Ticketing integration

---

## 🧠 SOC Skills Demonstrated

* SIEM alert engineering (Splunk)
* Log analysis & correlation
* SOAR automation (n8n)
* Incident triage logic
* Webhook integrations
* SOC alert hygiene

---

