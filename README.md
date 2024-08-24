# Scripting and Threat-Hunting

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


## Defender For Endpoint

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


## Azure Sentinel

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


















<ul>
  <li></li>
  <li></li>
  <li></li>
<li></li>
</ul>




