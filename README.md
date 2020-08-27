# KM.Snmp
This library is meant work on top of KM.Lextm.SharpSnmp (a fork of Lextm.SharpSnmp) which easily allows you to do SNMP commands get/set/getbulk/getsubree

In order to create an instance of CustomSnmp to make these calls, you will need to pass it an `ISnmpLog` and an `ILogger`
The purpose of the ISnmpLog is to log each SNMP transaction however you choose. An ISnmpLog will need to contain a function with the following signature:
````c#
Task LogTransactionAsync(DateTime startDate, string ip, string oid, string communityString, string snmpType, string snmpVersion, string returnType, string returnData);
````

Simple SNMPv2 Get Example:
````c#
Variable result = await CustomSnmp.GetV2Async(ip, oid, communityString, retries, port, timeout);
if(result is null)
{
    throw new Exception("Snmp Failed");
}

SnmpType type = result.Data.TypeCode;
ISnmpData data = result.Data;
if(type != SnmpType.Success)
{
    throw new Exception("Snmp Failed");
}

return data.ToString();
````

Simple SNMPv3 TSM Over DTLS Example:
````C#
Variable result = await _CustomSnmp.GetV3TsmAsync(ip, oid, retries, port, timeout, x509Certificate, connectionTimeout);
if(result is null)
{
    throw new Exception("Snmp Failed");
}

SnmpType type = result.Data.TypeCode;
ISnmpData data = result.Data;
if(type != SnmpType.Success)
{
    throw new Exception("Snmp Failed");
}

return data.ToString();
````

**Please note that SNMPv3 USM has not been tested.**  
Simple SNMPv3 USM Example:
````C#
Variable result = await _CustomSnmp.GetV3UsmAsync(ip, oid, communityString, retries, port, timeout, authPassword, privacyPassword);
if(result is null)
{
    throw new Exception("Snmp Failed");
}

SnmpType type = result.Data.TypeCode;
ISnmpData data = result.Data;
if(type != SnmpType.Success)
{
    throw new Exception("Snmp Failed");
}

return data.ToString();
````
