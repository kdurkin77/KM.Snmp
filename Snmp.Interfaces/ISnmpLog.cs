using System;
using System.Threading.Tasks;

namespace KM.Snmp.Interfaces
{
    public interface ISnmpLog : IDisposable
    {
        Task LogTransactionAsync(DateTime startDate, string ip, string oid, string communityString, string snmpType, string snmpVersion,
            string returnType, string returnData);
    }
}
