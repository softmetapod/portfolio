# Elastic SIEM Lab

## Objective

To deploy and configure a complete SIEM (Security Information and Event Management) environment using the Elastic Stack — from initial cloud deployment and agent configuration through event generation, log analysis, dashboard visualization, and alert rule creation.

## Tools & Technologies

- Elastic Cloud (Elasticsearch + Kibana)
- Elastic Agent with Elastic Defend integration
- Kali Linux (VirtualBox/VMware)
- Nmap

---

## Task 1: Set Up an Elastic Cloud Deployment

**Objective:** Create a free Elastic Cloud account and deploy an Elasticsearch instance.

**Steps:**
1. Register for a free trial at Elastic Cloud.
2. Log into the Elastic Cloud console.
3. Start the free trial and create an Elasticsearch deployment.
4. Choose the appropriate region and deployment size.
5. Complete the deployment setup and click "continue."

![Elastic Cloud Console Deployment](../Images/account1.png)

---

## Task 2: Set Up the Kali Linux VM

**Objective:** Install and configure a Kali Linux VM to serve as the monitored endpoint.

**Steps:**
1. Download the Kali Linux VM image.
2. Create a new VM in VirtualBox or VMware and import the Kali image.
3. Boot the VM and log in using default credentials.

![Kali Linux VM Running](../Images/kaliss.png)

---

## Task 3: Install the Elastic Agent for Log Collection

**Objective:** Deploy the Elastic Agent on the Kali VM to collect and forward security logs to the SIEM.

**Steps:**
1. Navigate to the Integrations page in the Elastic SIEM instance.
2. Find and install the "Elastic Defend" integration.
3. Copy the provided installation command and run it in the Kali terminal.
4. Verify successful agent enrollment.

![Elastic Agent Installation Message](../Images/install.png)

---

## Task 4: Generate Security Events with Nmap

**Objective:** Use Nmap to generate security-related events that will be captured by the SIEM.

**Steps:**
1. Install Nmap on the Kali VM if not already present.
2. Run various Nmap scans against specified targets (e.g., SYN scans, service detection, OS fingerprinting).
3. These scans produce network events that the Elastic Agent forwards to the SIEM for analysis.

![Nmap Command Execution](../Images/nmap1.png)

---

## Task 5: Query Security Events in Elastic SIEM

**Objective:** Query and analyze the ingested logs to identify the Nmap scan activity.

**Steps:**
1. Navigate to the "Logs" tab in the Elastic deployment.
2. Enter search queries to filter logs related to Nmap scan events.
3. Execute the search and review the results to confirm event ingestion.

![Search Query and Log Results](../Images/log1.png)

---

## Task 6: Build a Dashboard to Visualize Events

**Objective:** Create an interactive dashboard in Elastic SIEM to visualize security event patterns.

**Steps:**
1. Access the Elastic web portal and navigate to "Dashboards."
2. Create a new dashboard and add visualizations (bar charts, line graphs, data tables).
3. Configure the visualization to display event counts over time, grouped by event type.

![Completed Dashboard](../Images/graph1.png)

---

## Task 7: Create an Alert Rule

**Objective:** Set up an automated alert rule to detect Nmap scan activity in real time.

**Steps:**
1. Go to "Alerts" under "Security" and select "Manage Rules."
2. Create a new custom query rule targeting Nmap-related event signatures.
3. Configure the alert actions (notification, severity level) and enable the rule.

![Alert Configuration and Rule Creation](../Images/alert1.png)

---

## Key Takeaways

- Deployed a full Elastic SIEM environment from scratch, including cloud infrastructure and endpoint agent configuration.
- Generated realistic security events using Nmap and verified end-to-end log ingestion into the SIEM.
- Built custom KQL queries to search and filter security events, demonstrating log analysis skills.
- Created interactive dashboards for visualizing event trends and patterns over time.
- Configured automated alert rules for real-time detection of suspicious network activity.
