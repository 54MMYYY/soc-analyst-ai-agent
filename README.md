# Junior SOC Analyst AI Agent

An automated Security Operations Center (SOC) analyst agent that monitors 
network traffic, detects suspicious activity, and uses AI to analyze threats.

## How It Works

1. **Capture** — tcpdump monitors the network interface for ICMP traffic
2. **Detect** — Flags any source IP sending more than 40 packets in 100 seconds
3. **Alert** — Generates a structured JSON alert with evidence
4. **Analyze** — Sends the alert to Airia AI for threat classification

## Setup

### Requirements
- Ubuntu (internal server / victim machine)
- Kali Linux (attacker machine)
- Both VMs on the same network (Bridged adapter)
- Python 3, tcpdump installed
- Airia AI account and API key

### Installation

```bash
sudo apt install tcpdump python3-pip -y
pip3 install requests
```

### Configuration

Edit `new_soc_capture.py` and set:
```python
INTERFACE = "enp0s3"          # your network interface
DESTINATION_IP = "x.x.x.x"   # your Ubuntu IP
AIRIA_API_URL = "your-url"
AIRIA_API_KEY = "your-key"
```

### Running

On Ubuntu (victim/server):
```bash
sudo python3 new_soc_capture.py
```

On Kali (attacker) — to trigger the alert:
```bash
ping <ubuntu-ip> -c 60
```
## Screenshots

### 1. Airia AI Agent Workflow Test Input
Test alert JSON manually submitted to the Airia AI pipeline to verify the agent receives and processes the input correctly.
<img width="1275" height="703" alt="11" src="https://github.com/user-attachments/assets/886ecddb-21a3-4b5b-8ef8-93324140dfbe" />

### 2. Airia AI Agent Workflow Test Output
AI-generated threat analysis response from Airia, classifying the suspicious IP activity and recommending SOC actions.
<img width="1277" height="708" alt="12" src="https://github.com/user-attachments/assets/f61c1f90-e46b-42e5-8ced-938be29a6baf" />

### 3. Network Configuration — Ubuntu (Internal Server)
Network configuration of the Ubuntu internal server VM, showing its assigned IP address `192.168.8.106` on the bridged network.
<img width="1007" height="485" alt="3" src="https://github.com/user-attachments/assets/3fbebe1b-8ebd-42b6-a6cd-7581649a4068" />

### 4. Network Configuration — Kali Linux (Attacker)
Network configuration of the Kali Linux attacker VM, showing its assigned IP address `192.168.8.103` on the same subnet as Ubuntu.
<img width="787" height="400" alt="4" src="https://github.com/user-attachments/assets/93c5cbae-2473-41ec-8e7e-f6d38f1fac6b" />

### 5. SOC Agent Script Launched on Ubuntu
SOC agent script launched on Ubuntu, beginning a 100-second tcpdump capture session listening for incoming ICMP traffic.
<img width="840" height="88" alt="16" src="https://github.com/user-attachments/assets/9cd1efb9-ba46-40b8-99af-ddb3b5215545" />

### 6. ICMP Flood Attack from Kali
Simulated ICMP flood attack launched from the Kali attacker machine, sending 50 packets to the Ubuntu server to trigger the detection threshold.

<img width="542" height="467" alt="7" src="https://github.com/user-attachments/assets/1b899fb5-7115-4194-a586-ecf526838cf9" />

### 7. Ubuntu Output — Part 1
Script detects the suspicious source IP exceeding the 40-packet threshold, generates a structured JSON alert and sends it to the Airia AI API.
<img width="865" height="392" alt="13" src="https://github.com/user-attachments/assets/460850ac-1fec-4b75-98d9-c1060202e8fd" />

### 8. Ubuntu Output — Part 2
Airia AI responds with status 200, returning a full threat classification report including risk score, MITRE mapping and recommended actions.
<img width="1244" height="689" alt="14" src="https://github.com/user-attachments/assets/27223c9a-5f40-473a-b644-71a17a67e5a7" />

### 9. Airia AI Execution Logs
Airia AI dashboard showing the pipeline execution history, confirming the alert was successfully received, processed and logged by the AI agent.
<img width="1015" height="211" alt="15" src="https://github.com/user-attachments/assets/9eaaf354-e0bb-4c56-bb3e-6b526d85e795" />

## Files

| File | Description |
|------|-------------|
| `new_soc_capture.py` | Main agent script |
| `instructions.txt` | Full setup documentation |
| `Testing Input and Output.txt` | AIRIA AI Agent's Test Input and Output |

## Tech Stack
- Python 3
- tcpdump
- Airia AI API
- Kali Linux + Ubuntu (VMware + VirtualBox)
