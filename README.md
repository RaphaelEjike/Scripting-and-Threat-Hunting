# KQL threat hunting

## Understanding KQL and Its Use in Microsoft Defender for Endpoints and Azure Sentinel

Kusto Query Language (KQL) is a powerful query language developed by Microsoft for extracting and analyzing large datasets. It is widely used in various Microsoft services, including Microsoft Defender for Endpoints and Microsoft Azure Sentinel, to perform advanced hunting and threat detection.

## Using KQL in Microsoft Defender for Endpoints
In Microsoft Defender for Endpoints (security.microsoft.com), KQL is used for advanced hunting. This feature allows security analysts to proactively search through raw data to identify potential threats. 

## Using KQL in Microsoft Azure Sentinel
Microsoft Sentinel (portal.azure.com) leverages KQL for custom detection rules and hunting queries. Analysts can create complex queries to detect suspicious activities and visualize data.

## Slight syntax difference between Defender for Endpoint and Azure Sentinel

KQL queries can be used in both Defender For Endpoint and Azure Sentinel. The syntax is almost the same. The main difference is the field that indicates the time. It must be adjusted according to the product used. In DFE it is 'Timestamp'. In Sentinel, the 'TimeGenerated' field is used. The queries below show both in DFE and in Sentinel 10 DeviceEvents of the last 7 days.


Defender For Endpoint
```
DeviceEvents
| where Timestamp > ago(7d)
| take 10
```
Azure Sentinel
```
DeviceEvents
| where TimeGenerated > ago(7d)
| take 10
```

# KQL Queries with Explanations and Use Cases

Here are 10 common KQL queries used during a data breach due to phishing and malware, including user activities, network traffic, and system events, using data from Azure Active Directory logs and Defender for Endpoint alerts. Each query includes placeholders for malicious indicators and step-by-step explanations.

## Defender for Endpoints 

<ul>
  <li>Malware Alerts by Device</li>
  <li>Suspicious URL Access</li>
    <li>Unusual Data Transfers</li>
  <li>Phishing Email Clicks</li>
    <li>Suspicious Processes</li>
</ul>

## Azure Sentinel 

<ul>
  <li>Suspicious Logins by User</li>
  <li>Failed Login Attempts</li>
    <li>Admin Activities</li>
  <li>Elevated Privileges</li>
    <li>Endpoint Alert Summary</li>
</ul>


# Defender For Endpoint

### Malware Alerts by Device
Use Case: Tracks devices affected by known malware.
```
DeviceEvents
| where Timestamp >= ago(24h)
| where FileHash in ('{MaliciousHash}')
| summarize AlertCount = count() by DeviceName, FileHash
```
Explanation:
<ul>
  <li>DeviceEvents: Table containing device-related events.</li>
  <li>Timestamp >= ago(24h): Filter to the last 24 hours.</li>
  <li>FileHash in ('{MaliciousHash}'): Filter by malicious file hashes.</li>
<li>summarize AlertCount = count() by DeviceName, FileHash: Summarize alert counts by device and file hash.</li>
</ul>


### Suspicious URL Access
Use Case: Identifies devices accessing known phishing or malicious sites.
```
DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where RemoteUrl in ('{MaliciousURL}')
| summarize AccessCount = count() by DeviceName, RemoteUrl
```
Explanation:
<ul>
  <li>DeviceNetworkEvents: Table containing network events.</li>
  <li>Timestamp >= ago(24h): Filter to the last 24 hours.</li>
  <li>RemoteUrl in ('{MaliciousURL}'): Filter by malicious URLs.</li>
<li>summarize AccessCount = count() by DeviceName, RemoteUrl: Summarize access counts by device and URL.</li>
</ul>


### Unusual Data Transfers
Use Case: Identifies potential data exfiltration activities.
```
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCopied" or ActionType == "FileMoved"
| summarize TransferCount = count() by InitiatingProcessAccountName, DestinationDeviceName
```
Explanation:
<ul>
  <li>DeviceFileEvents: Table containing file events.</li>
  <li>Timestamp >= ago(24h): Filter to the last 24 hours.</li>
  <li>ActionType == "FileCopied" or ActionType == "FileMoved": Filter for file transfer actions.</li>
<li>summarize TransferCount = count() by InitiatingProcessAccountName, DestinationDeviceName: Summarize transfer counts by account and destination device.</li>
</ul>

###  Phishing Email Clicks
Use Case: Tracks users who clicked on phishing links.
```
EmailEvents
| where Timestamp >= ago(24h)
| where Url in ('{MaliciousURL}')
| summarize ClickCount = count() by RecipientEmailAddress, Url
```
Explanation:
<ul>
  <li>EmailEvents: Table containing email events.</li>
  <li>Timestamp >= ago(24h): Filter to the last 24 hours.</li>
  <li>Url in ('{MaliciousURL}'): Filter by malicious URLs.</li>
<li>summarize ClickCount = count() by RecipientEmailAddress, Url: Summarize click counts by recipient and URL.</li>
</ul>

### Suspicious Processes
Use Case: Detects potentially malicious processes running on devices.
```
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where InitiatingProcessFileName in ("powershell.exe", "cmd.exe", "{MaliciousProcess}")
| summarize ProcessCount = count() by DeviceName, InitiatingProcessFileName
```
Explanation:
<ul>
  <li>	DeviceProcessEvents: Table containing process events.</li>
  <li>Timestamp >= ago(24h): Filter to the last 24 hours.</li>
  <li>InitiatingProcessFileName in ("powershell.exe", "cmd.exe", "{MaliciousProcess}"): Filter for specific processes.</li>
<li>summarize ProcessCount = count() by DeviceName, InitiatingProcessFileName: Summarize process counts by device and process.</li>
</ul>

# Azure Sentinel

### Suspicious Logins by User
Use Case: Identifies suspicious login attempts from known malicious IP addresses.
```
SigninLogs
| where TimeGenerated >= ago(24h)
| where IPAddress in ('{MaliciousIP}')
| summarize LoginCount = count() by UserPrincipalName, IPAddress

```
Explanation:

<ul>
  <li>SigninLogs: Table containing login records.</li>
  <li>TimeGenerated >= ago(24h): Filter to the last 24 hours.</li>
  <li>IPAddress in ('{MaliciousIP}'): Filter by malicious IP addresses.</li>
<li>summarize LoginCount = count() by UserPrincipalName, IPAddress: Summarize login counts by user and IP address.</li>
</ul>



### Failed Login Attempts
Use Case: Detects accounts targeted by brute-force attacks.
```
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "50126" or ResultType == "50076"
| summarize FailedAttempts = count() by UserPrincipalName
```
Explanation:

<ul>
  <li>SigninLogs: Table containing login records.</li>
  <li>TimeGenerated >= ago(24h): Filter to the last 24 hours.</li>
  <li>ResultType == "50126" or ResultType == "50076": Filter for specific failed login codes.</li>
<li>	summarize FailedAttempts = count() by UserPrincipalName: Summarize failed login attempts by user.</li>
</ul>

### Admin Activities
Use Case: Monitors potentially malicious administrative activities.
```
AuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName in ("Add member to role", "Reset password", "Delete user")
| summarize ActivityCount = count() by InitiatedBy
```
Explanation:

<ul>
  <li>AuditLogs: Table containing audit logs.</li>
  <li>TimeGenerated >= ago(24h): Filter to the last 24 hours.</li>
  <li>OperationName in ("Add member to role", "Reset password", "Delete user"): Filter for specific admin activities.</li>
<li>summarize ActivityCount = count() by InitiatedBy: Summarize activity counts by initiator.</li>
</ul>

### Elevated Privileges
Use Case: Detects unusual or suspicious logins by admin accounts.
```
AADSignInLogs
| where TimeGenerated >= ago(24h)
| where UserPrincipalName contains "admin"
| where ResultType == 0
| summarize PrivilegedLogins = count() by UserPrincipalName, AppDisplayName
```
Explanation:
<ul>
  <li>AADSignInLogs: Table containing Azure AD sign-in logs.</li>
  <li>TimeGenerated >= ago(24h): Filter to the last 24 hours.</li>
  <li>UserPrincipalName contains "admin": Filter for admin accounts.</li>
<li>ResultType == 0: Filter for successful logins.</li>
  <li>summarize PrivilegedLogins = count() by UserPrincipalName, AppDisplayName: Summarize privileged logins by user and application.</li>
</ul>


### Endpoint Alert Summary
Use Case: Provides a summary of significant security alerts.
```
SecurityAlert
| where TimeGenerated >= ago(24h)
| where AlertSeverity in ("High", "Medium")
| summarize AlertCount = count() by CompromisedEntity, AlertSeverity
```
Explanation:
<ul>
  <li>SecurityAlert: Table containing security alerts.</li>
  <li>TimeGenerated >= ago(24h): Filter to the last 24 hours.</li>
  <li>AlertSeverity in ("High", "Medium"): Filter for high and medium severity alerts.</li>
<li>summarize AlertCount = count() by CompromisedEntity, AlertSeverity: Summarize alert counts by compromised entity and severity.</li>
</ul>


## Interpreting Summary Statistics

For each query, the summary statistics provide a count of events grouped by relevant categories (e.g., user, device, IP address). Here's how to interpret them:

<ul>
  <li>1.	Login Counts: Higher counts of logins from malicious IPs may indicate a targeted attack.</li>
<li>2.	Alert Counts: Frequent alerts related to specific devices or files can signal compromised endpoints.</li>
  <li>3.	Failed Attempts: A high number of failed logins can suggest brute-force attacks.</li>
<li>4.	Access Counts: Repeated access to malicious URLs can indicate phishing activity.</li>
  <li>5.	Activity Counts: Unusual admin activities may point to privilege escalation.</li>
<li>6.	Privileged Logins: Multiple logins by admin accounts need to be verified for legitimacy.</li>
  <li>7.	Transfer Counts: Unusual data transfer activity might be a sign of data exfiltration.</li>
<li>8.	Click Counts: Users clicking on phishing links should be warned and investigated.</li>
  <li>9.	Alert Severity: A summary of high and medium alerts helps prioritize incident response.</li>
<li>10.	Process Counts: Monitoring suspicious processes can reveal malware behavior.
</li>
</ul>
    
Resources 
 
- <a href="https://github.com/RaphaelEjike/ThreatHunting ">My KQL threat hunting workflows (Private)</a>
- <a href="https://www.kqlsearch.com/">www.kqlsearch.com</a>
- <a href="https://learn.microsoft.com/en-us/kusto/query/tutorials/learn-common-operators?view=azure-data-explorer&preserve-view=true&pivots=azuredataexplorer">Kusto query tutorials</a>
- <a href="https://kqlquery.com/">https://kqlquery.com/</a>
- <a href="https://kqlquery.com/posts/kql_sources/">https://kqlquery.com/posts/kql_sources/</a>
- <a href="https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf">https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet_dark.pdf</a>

