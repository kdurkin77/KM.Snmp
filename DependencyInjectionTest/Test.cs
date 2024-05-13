using KM.Snmp;
using Lextm.SharpSnmpLib;
using System;
using System.Net;
using System.Threading.Tasks;

namespace DependencyInjectionTest
{
    public class Test
    {
        private readonly CustomSnmp _CustomSnmp;

        public Test(CustomSnmp customSnmp)
        {
            _CustomSnmp = customSnmp;
        }

        public async Task RunAsync()
        {
            var ip = IPAddress.Parse("");
            var oid = "";
            var communityString = "";
            var retries = 1;
            var port = 161;
            var timeout = TimeSpan.FromSeconds(5);

            var result = await _CustomSnmp.GetV2Async(ip, oid, communityString, retries, port, timeout) ?? throw new Exception("Snmp Failed");
            var type = result.Data.TypeCode;
            var data = result.Data;
            if (type != SnmpType.OctetString)
            {
                throw new Exception("Snmp Failed");
            }

            Console.WriteLine(data);
        }
    }
}
