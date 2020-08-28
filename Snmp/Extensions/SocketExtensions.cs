#if NETSTANDARD2_0
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KM.Snmp.Extensions
{
    internal static class SocketExtensions
    {
        public static Task<int> SendAsync(this Socket socket, byte[] buffer, SocketFlags socketFlags, CancellationToken cancellationToken) =>
            Task.Factory.FromAsync(
                socket.BeginSend(buffer, 0, buffer.Length, socketFlags, null, socket),
                socket.EndReceive
                );

        public static Task<int> ReceiveAsync(this Socket socket, byte[] buffer, SocketFlags socketFlags, CancellationToken cancellationToken) =>
            Task.Factory.FromAsync(
                socket.BeginReceive(buffer, 0, buffer.Length, socketFlags, null, socket),
                socket.EndReceive
                );
    }
}
#endif