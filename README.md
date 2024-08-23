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




