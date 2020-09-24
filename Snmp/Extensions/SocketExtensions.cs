using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Sockets
{
    internal static class SocketExtensions
    {
#if NETSTANDARD2_0
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
#endif
        public static async Task ConnectAsync(this Socket socket, IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            var connectTask = socket.ConnectAsync(endpoint);
            if (connectTask == await Task.WhenAny(connectTask, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false))
            {
                await connectTask.ConfigureAwait(false);
            }
            else
            {
                throw new TaskCanceledException();
            }
        }
    }
}