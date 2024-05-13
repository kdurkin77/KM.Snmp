using KM.Snmp;
using KM.Snmp.Interfaces;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Test
{
    public class Program
    {
        public static async Task Main(string[] _)
        {
            //basic parameters
            var ip = IPAddress.Parse("");
            var oid = "";
            var communityString = "";
            var retries = 1;
            var port = 161;
            var timeout = TimeSpan.FromSeconds(5);

            //SNMPv3 Parameters
            var certFilename = "";
            var certificate = new X509Certificate2(certFilename);
            var connectionTimeout = TimeSpan.FromSeconds(2);

            //Set Value can be int, string (octetstring), IPAddress, byte[], or uint
            var setValue = 1;

            //GetSubtree parameters
            var maxRepetitions = 5;

            var myCustomSnmp = new CustomSnmp(new SnmpLogger(), new Logger());

            //SNMPv2 Get
            var getV2Result = await myCustomSnmp.GetV2Async(ip, oid, communityString, retries, port, timeout);
            if (getV2Result is null || getV2Result.Data is null)
            {
                throw new Exception("Snmp Failed");
            }

            var getV2Type = getV2Result.Data.TypeCode;
            var getV2Data = getV2Result.Data;
            if (getV2Type != SnmpType.OctetString)
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv2 Get result: {getV2Data}");

            //SNMPv3 TSM Get
            var getV3Result = await myCustomSnmp.GetV3TsmAsync(ip, oid, retries, port, timeout, certificate, connectionTimeout);
            if (getV3Result is null || getV3Result.Data is null)
            {
                throw new Exception("Snmp Failed");
            }

            var getV3Type = getV3Result.Data.TypeCode;
            var getV3Data = getV3Result.Data;
            if (getV3Type != SnmpType.OctetString)
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv3 TSM Get result: {getV3Data}");

            //SNMPv2 Set
            var setV2Result = await myCustomSnmp.SetV2Async(ip, oid, communityString, retries, port, timeout, setValue);
            if (setV2Result is null || setV2Result.Pdu() is null)
            {
                throw new Exception("Snmp Failed");
            }

            var setV2Data = setV2Result.Pdu().ErrorStatus;
            if (setV2Data != new Integer32(0))
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv2 Get result: {setV2Data}");

            //SNMPv3 TSM set
            var setV3Result = await myCustomSnmp.SetV3TsmAsync(ip, oid, retries, port, timeout, certificate, connectionTimeout, setValue);
            if (setV3Result is null || setV3Result.Pdu() is null)
            {
                throw new Exception("Snmp Failed");
            }

            var setV3Data = setV3Result.Pdu().ErrorStatus;
            if (setV3Data != new Integer32(0))
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv3 TSM Get result: {setV3Data}");

            //SNMPv2 GetSubtree
            var (v2BulkwalkResult, v2Results) = await myCustomSnmp.GetSubtreeV2Async(ip, oid, communityString, port, maxRepetitions, retries, timeout);
            if (v2Results is null || !v2Results.Any())
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv2 GetSubtree result count: {v2BulkwalkResult}");
            foreach (var result in v2Results)
            {
                Console.WriteLine($"SNMPv2 GetSubtree results: {result.Data}");
            }

            //SNMPv3 GetSubtree
            var (v3BulkwalkResult, v3Results) = await myCustomSnmp.GetSubtreeV3TsmAsync(ip, oid, port, maxRepetitions, retries, timeout, certificate, connectionTimeout);
            if (v3Results is null || !v3Results.Any())
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine($"SNMPv2 GetSubtree result count: {v3BulkwalkResult}");
            foreach (var result in v3Results)
            {
                Console.WriteLine($"SNMPv2 GetSubtree results: {result.Data}");
            }
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

        private static readonly DummyScope _dummyScope = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return _dummyScope;
        }

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            //Log here
        }

    }
}
