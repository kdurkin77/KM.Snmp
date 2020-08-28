using KM.Snmp;
using KM.Snmp.Interfaces;
using Lextm.SharpSnmpLib;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Test
{
    public class Program
    {
        public static async Task Main(string[] _)
        {
            var ip = IPAddress.Parse("");
            var oid = "";
            var communityString = "";
            var retries = 1;
            var port = 161;
            var timeout = TimeSpan.FromSeconds(5);

            var myCustomSnmp = new CustomSnmp(new SnmpLogger(), new Logger());
            var result = await myCustomSnmp.GetV2Async(ip, oid, communityString, retries, port, timeout);
            if (result is null)
            {
                throw new Exception("Snmp Failed");
            }

            var type = result.Data.TypeCode;
            var data = result.Data;
            if (type != SnmpType.OctetString)
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine(data);
        }
    }

    public class SnmpLogger : ISnmpLog, IDisposable
    {
        private bool _disposed = false;

        public Task LogTransactionAsync(DateTime startDate, string ip, string oid, string communityString, string snmpType, string snmpVersion, string returnType, string returnData)
        {
            //Log Here
            return Task.CompletedTask;
        }

        ~SnmpLogger() => Dispose(false);

        private void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                //Dispose unmanaged resources here
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public class Logger : ILogger<CustomSnmp>
    {
        private sealed class DummyScope : IDisposable
        {
            public void Dispose() { }
        }

        private static readonly DummyScope _dummyScope = new DummyScope();

        public IDisposable BeginScope<TState>(TState state)
        {
            return _dummyScope;
        }

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            //Log here
        }

    }
}
