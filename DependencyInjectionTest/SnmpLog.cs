using KM.Snmp.Interfaces;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DependencyInjectionTest
{
    public sealed class SnmpLog : ISnmpLog
    {
        private bool _disposed = false;

        ~SnmpLog() => Dispose(false);

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SnmpLog));
            }
        }

        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                //Dispose Unused Resources Here
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private readonly Lazy<IPAddress> _localIpAddress = new(() =>
            Dns.GetHostEntry(Dns.GetHostName()).AddressList
                .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                .FirstOrDefault() ?? IPAddress.Loopback
            );

        private IPAddress GetLocalIPAddress()
        {
            return _localIpAddress.Value;
        }

        public Task LogTransactionAsync(DateTime startDate, string ip, string oid, string communityString, string snmpType, string snmpVersion, string returnType, string returnData)
        {
            //Log Here
            return Task.CompletedTask;
        }
    }
}
