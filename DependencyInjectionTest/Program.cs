using KM.Snmp;
using KM.Snmp.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace DependencyInjectionTest
{
    public class Program
    {
        public static async Task Main(string[] _)
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddSingleton<ISnmpLog, SnmpLog>()
                .AddSingleton<CustomSnmp>()
                .AddSingleton<Test>()
                .BuildServiceProvider();

            var test = services.GetRequiredService<Test>();
            await test.RunAsync().ConfigureAwait(false);
        }
    }
}
