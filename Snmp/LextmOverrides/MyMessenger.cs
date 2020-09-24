using DTLS;
using Lextm.SharpSnmpLib.Security;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Lextm.SharpSnmpLib.Messaging
{
    public static class MyMessenger
    {
        private static readonly NumberGenerator _RequestCounter = new NumberGenerator(int.MinValue, int.MaxValue);
        private static readonly NumberGenerator _MessageCounter = new NumberGenerator(0, int.MaxValue);
        private static readonly ObjectIdentifier _IdNotInTimeWindow = new ObjectIdentifier(new uint[] { 1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0 });

        public static async Task<IList<Variable>> GetAsync(VersionCode version, IPEndPoint endpoint, OctetString community, IList<Variable> variables, TimeSpan timeout)
        {
            if (version == VersionCode.V3)
            {
                throw new NotSupportedException("SNMP v3 is not supported");
            }

            if (endpoint == null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            if (community == null)
            {
                throw new ArgumentNullException(nameof(community));
            }

            if (variables == null)
            {
                throw new ArgumentNullException(nameof(variables));
            }

            if (timeout < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), $"{timeout}");
            }

            using var cts = new CancellationTokenSource(timeout);
            var message = new GetRequestMessage(_RequestCounter.NextId, version, community, variables);
            var response = await message.GetResponseAsync(endpoint, cts.Token).ConfigureAwait(false);
            var pdu = response.Pdu();
            if (pdu.ErrorStatus.ToInt32() != 0)
            {
                throw ErrorException.Create(
                    "error in response",
                    endpoint.Address,
                    response);
            }

            return pdu.Variables;
        }

        public static async Task<int> BulkWalkV2Async(IPEndPoint endpoint, OctetString community, ObjectIdentifier table, IList<Variable> list,
            int maxRepetitions, int retries, TimeSpan timeout, WalkMode mode, IPrivacyProvider? privacy, ISnmpMessage? report)
        {
            if (endpoint is null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            if (community is null)
            {
                throw new ArgumentNullException(nameof(community));
            }

            if(table is null)
            {
                throw new ArgumentNullException(nameof(table));
            }

            if (list is null)
            {
                throw new ArgumentNullException(nameof(list));
            }

            if(maxRepetitions < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), $"{maxRepetitions}");
            }

            if(retries < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), $"{retries}");
            }

            if(timeout < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), $"{timeout}");
            }

            var tableV = new Variable(table);
            var seed = tableV;
            var result = 0;
            IList<Variable> next;
            var message = report;
            var data = await BulkHasNextV2Async(endpoint, community, seed, maxRepetitions, retries, timeout, privacy, message).ConfigureAwait(false);
            next = data.Item2;
            message = data.Item3;
            while (data.Item1)
            {
                var subTreeMask = string.Format(CultureInfo.InvariantCulture, "{0}.", table);
                var rowMask = string.Format(CultureInfo.InvariantCulture, "{0}.1.1.", table);
                foreach (var v in next)
                {
                    var id = v.Id.ToString();
                    if (v.Data.TypeCode == SnmpType.EndOfMibView)
                    {
                        return result;
                    }

                    if (mode == WalkMode.WithinSubtree && !id.StartsWith(subTreeMask, StringComparison.Ordinal))
                    {
                        // not in sub tree
                        return result;
                    }

                    list.Add(v);
                    if (id.StartsWith(rowMask, StringComparison.Ordinal))
                    {
                        result++;
                    }
                }

                seed = next[next.Count - 1];
                data = await BulkHasNextV2Async(endpoint, community, seed, maxRepetitions, retries, timeout, privacy, message).ConfigureAwait(false);
                next = data.Item2;
                message = data.Item3;
            }

            return result;
        }

        public static async Task<int> BulkWalkV3UsmAsync(IPEndPoint endpoint, OctetString community, ObjectIdentifier table, IList<Variable> list,
            int maxRepetitions, int retries, TimeSpan timeout, WalkMode mode, IPrivacyProvider privacy, ISnmpMessage report)
        {
            if (endpoint is null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            if (community is null)
            {
                throw new ArgumentNullException(nameof(community));
            }

            if (table is null)
            {
                throw new ArgumentNullException(nameof(table));
            }

            if (list is null)
            {
                throw new ArgumentNullException(nameof(list));
            }

            if (maxRepetitions < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), $"{maxRepetitions}");
            }

            if (retries < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), $"{retries}");
            }

            if (timeout < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), $"{timeout}");
            }

            var tableV = new Variable(table);
            var seed = tableV;
            var result = 0;
            IList<Variable> next;
            var message = report;
            var data = await BulkHasNextV3UsmAsync(endpoint, community, seed, maxRepetitions, retries, timeout, privacy, message).ConfigureAwait(false);
            next = data.Item2;
            message = data.Item3;
            while (data.Item1)
            {
                var subTreeMask = string.Format(CultureInfo.InvariantCulture, "{0}.", table);
                var rowMask = string.Format(CultureInfo.InvariantCulture, "{0}.1.1.", table);
                foreach (var v in next)
                {
                    var id = v.Id.ToString();
                    if (v.Data.TypeCode == SnmpType.EndOfMibView)
                    {
                        return result;
                    }

                    if (mode == WalkMode.WithinSubtree && !id.StartsWith(subTreeMask, StringComparison.Ordinal))
                    {
                        // not in sub tree
                        return result;
                    }

                    list.Add(v);
                    if (id.StartsWith(rowMask, StringComparison.Ordinal))
                    {
                        result++;
                    }
                }

                seed = next[next.Count - 1];
                data = await BulkHasNextV3UsmAsync(endpoint, community, seed, maxRepetitions, retries, timeout, privacy, message).ConfigureAwait(false);
                next = data.Item2;
                message = data.Item3;
            }
            return result;
        }

        public static async Task<int> BulkWalkV3TsmAsync(IPEndPoint endpoint, ObjectIdentifier table, IList<Variable> list,  
            int maxRepetitions, int retries, TimeSpan timeout, WalkMode mode, IPrivacyProvider privacy, ISnmpMessage? report, X509Certificate2 certificate, TimeSpan? connectionTimeout)
        {
            if (endpoint is null)
            {
                throw new ArgumentNullException(nameof(endpoint));
            }

            if (table is null)
            {
                throw new ArgumentNullException(nameof(table));
            }

            if (list is null)
            {
                throw new ArgumentNullException(nameof(list));
            }

            if (maxRepetitions < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), $"{maxRepetitions}");
            }

            if (retries < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), $"{retries}");
            }

            if (timeout < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), $"{timeout}");
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var tableV = new Variable(table);
            var seed = tableV;
            var result = 0;
            IList<Variable> next;
            var message = report;
            var data = await BulkHasNextV3TsmAsync(endpoint, seed, maxRepetitions, retries, timeout, privacy, message, certificate, connectionTimeout).ConfigureAwait(false);
            next = data.Item2;
            message = data.Item3;
            while (data.Item1)
            {
                var subTreeMask = string.Format(CultureInfo.InvariantCulture, "{0}.", table);
                var rowMask = string.Format(CultureInfo.InvariantCulture, "{0}.1.1.", table);
                foreach (var v in next)
                {
                    var id = v.Id.ToString();
                    if (v.Data.TypeCode == SnmpType.EndOfMibView)
                    {
                        return result;
                    }

                    if (mode == WalkMode.WithinSubtree && !id.StartsWith(subTreeMask, StringComparison.Ordinal))
                    {
                        // not in sub tree
                        return result;
                    }

                    list.Add(v);
                    if (id.StartsWith(rowMask, StringComparison.Ordinal))
                    {
                        result++;
                    }
                }

                seed = next[next.Count - 1];
                data = await BulkHasNextV3TsmAsync(endpoint, seed, maxRepetitions, retries, timeout, privacy, message, certificate, connectionTimeout).ConfigureAwait(false);
                next = data.Item2;
                message = data.Item3;
            }

            return result;
        }

        public static int MaxMessageSize { get; set; } = Header.MaxMessageSize;

        private static async Task<Tuple<bool, IList<Variable>, ISnmpMessage>> BulkHasNextV2Async(IPEndPoint receiver, OctetString community,
            Variable seed, int maxRepetitions, int retries, TimeSpan timeout, IPrivacyProvider? privacy, ISnmpMessage? report)
        {
            var completedRetries = 0;
            while (retries > completedRetries)
            {
                try
                {
                    var variables = new List<Variable> { new Variable(seed.Id) };
                    var request = new GetBulkRequestMessage(_RequestCounter.NextId, VersionCode.V2, community, 0, maxRepetitions, variables);
                    using var cts = new CancellationTokenSource(timeout);
                    var reply = await request.GetResponseAsync(receiver, cts.Token).ConfigureAwait(false);

                    if (reply is ReportMessage)
                    {
                        if (reply.Pdu().Variables.Count == 0)
                        {
                            // TODO: whether it is good to return?
                            return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        var id = reply.Pdu().Variables[0].Id;
                        if (id != _IdNotInTimeWindow)
                        {
                            // var error = id.GetErrorMessage();
                            // TODO: whether it is good to return?
                            return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        //according to RFC 3414, send a second request to sync time.
                        request = new GetBulkRequestMessage(
                            VersionCode.V2,
                            _MessageCounter.NextId,
                            _RequestCounter.NextId,
                            community,
                            0,
                            maxRepetitions,
                            variables,
                            privacy,
                            MaxMessageSize,
                            report);

                        using var cts2 = new CancellationTokenSource(timeout);
                        reply = await request.GetResponseAsync(receiver, cts2.Token).ConfigureAwait(false);
                    }
                    else if (reply.Pdu().ErrorStatus.ToInt32() != 0)
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            reply);
                    }

                    var next = reply.Pdu().Variables;
                    return new Tuple<bool, IList<Variable>, ISnmpMessage>(next.Count != 0, next, request);
                }
                catch (Exception ex) when (ex is TimeoutException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    completedRetries++;
                }
            }

            throw new OperationCanceledException();
        }

        private static async Task<Tuple<bool, IList<Variable>, ISnmpMessage>> BulkHasNextV3UsmAsync(IPEndPoint receiver, OctetString community,
            Variable seed, int maxRepetitions, int retries, TimeSpan timeout, IPrivacyProvider privacy, ISnmpMessage report)
        {
            var completedRetries = 0;
            while (retries > completedRetries)
            {
                try
                {
                    var variables = new List<Variable> { new Variable(seed.Id) };
                    var request = new GetBulkRequestMessage(VersionCode.V3, _MessageCounter.NextId, _RequestCounter.NextId, community, 0,
                        maxRepetitions, variables, privacy, MaxMessageSize, report);
                    using var cts = new CancellationTokenSource(timeout);
                    var reply = await request.GetResponseAsync(receiver, cts.Token).ConfigureAwait(false);

                    if (reply is ReportMessage)
                    {
                        if (reply.Pdu().Variables.Count == 0)
                        {
                            // TODO: whether it is good to return?
                            return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        var id = reply.Pdu().Variables[0].Id;
                        if (id != _IdNotInTimeWindow)
                        {
                            // var error = id.GetErrorMessage();
                            // TODO: whether it is good to return?
                            return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        //according to RFC 3414, send a second request to sync time.
                        request = new GetBulkRequestMessage(VersionCode.V3, _MessageCounter.NextId, _RequestCounter.NextId, community, 0,
                        maxRepetitions, variables, privacy, MaxMessageSize, report);

                        using var cts2 = new CancellationTokenSource(timeout);
                        reply = await request.GetResponseAsync(receiver, cts2.Token).ConfigureAwait(false);
                    }
                    else if (reply.Pdu().ErrorStatus.ToInt32() != 0)
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            reply);
                    }

                    var next = reply.Pdu().Variables;
                    return new Tuple<bool, IList<Variable>, ISnmpMessage>(next.Count != 0, next, request);
                }
                catch (Exception ex) when (ex is TimeoutException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    completedRetries++;
                }
            }

            throw new OperationCanceledException();
        }

        private static async Task<Tuple<bool, IList<Variable>, ISnmpMessage>> BulkHasNextV3TsmAsync(IPEndPoint receiver,
            Variable seed, int maxRepetitions, int retries, TimeSpan timeout, IPrivacyProvider privacy, ISnmpMessage? report, X509Certificate2 certificate, TimeSpan? connectionTimeout)
        {
            var completedRetries = 0;
            while (retries > completedRetries)
            {
                try
                {
                    var variables = new List<Variable> { new Variable(seed.Id) };
                    var request = new GetBulkRequestMessage(VersionCode.V3, _MessageCounter.NextId, _RequestCounter.NextId, OctetString.Empty, 0,
                        maxRepetitions, variables, privacy, MaxMessageSize);

                    var chain = new X509Chain();
                    chain.Build(certificate);
                    var endpoint = receiver.AddressFamily == AddressFamily.InterNetwork ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    using var client = new Client(endpoint);
                    client.LoadX509Certificate(chain);
                    client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
                    var connTimeout = connectionTimeout ?? TimeSpan.FromSeconds(1);
                    var reply = await request.GetSecureResponseAsync(connTimeout, timeout, receiver, client).ConfigureAwait(false);

                    if (reply is ReportMessage)
                    {
                        if (reply.Pdu().Variables.Count == 0)
                        {
                        // TODO: whether it is good to return?
                        return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        var id = reply.Pdu().Variables[0].Id;
                        if (id != _IdNotInTimeWindow)
                        {
                            // var error = id.GetErrorMessage();
                            // TODO: whether it is good to return?
                            return new Tuple<bool, IList<Variable>, ISnmpMessage>(false, new List<Variable>(0), report);
                        }

                        //according to RFC 3414, send a second request to sync time.
                        request = new GetBulkRequestMessage(VersionCode.V3, _MessageCounter.NextId, _RequestCounter.NextId, OctetString.Empty, 0,
                        maxRepetitions, variables, privacy, MaxMessageSize);
                        reply = await request.GetSecureResponseAsync(connTimeout, timeout, receiver, client).ConfigureAwait(false);
                    }
                    else if (reply.Pdu().ErrorStatus.ToInt32() != 0)
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            reply);
                    }

                    var next = reply.Pdu().Variables;
                    return new Tuple<bool, IList<Variable>, ISnmpMessage>(next.Count != 0, next, request);
                }
                catch (Exception ex) when (ex is TimeoutException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    completedRetries++;
                }
            }

            throw new OperationCanceledException();
        }
    }
}
