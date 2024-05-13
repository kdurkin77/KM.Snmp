#if !NET6_0_OR_GREATER

using Lextm.SharpSnmpLib.Security;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Lextm.SharpSnmpLib.Messaging
{
    public static class SnmpMessageExtensions
    {
        internal static async Task<ISnmpMessage> GetResponseAsync(this ISnmpMessage request, IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
        {
            try
            {
                using var socket = new Socket(remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                await socket.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(false);

                var sendingBytes = request.ToBytes();
                await socket.SendAsync(sendingBytes, SocketFlags.None, cancellationToken).ConfigureAwait(false);

                var recvd = new byte[100000];
                var recvdCount = await socket.ReceiveAsync(recvd, SocketFlags.None, cancellationToken).ConfigureAwait(false);

                var registry = new UserRegistry();
                var response = MessageFactory.ParseMessages(recvd.Take(recvdCount).ToArray(), 0, recvdCount, registry)[0];

                var responseCode = response.TypeCode();
                if (responseCode == SnmpType.ResponsePdu || responseCode == SnmpType.ReportPdu)
                {
                    var requestId = request.MessageId();
                    var responseId = response.MessageId();
                    if (responseId != requestId)
                    {
                        throw OperationException.Create($"wrong response sequence: expected {requestId}, received {responseId}", remoteEndPoint.Address);
                    }

                    return response;
                }

                throw OperationException.Create($"wrong response type: {responseCode}", remoteEndPoint.Address);
            }
            catch (TaskCanceledException)
            {
                throw new OperationCanceledException(cancellationToken);
            }
        }
    }
}

#endif
