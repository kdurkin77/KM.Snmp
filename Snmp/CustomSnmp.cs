using DTLS;
using KM.Snmp.Interfaces;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace KM.Snmp
{
    public class CustomSnmp
    {
        private readonly ISnmpLog _SnmpLog;
        private readonly ILogger _Logger;

        public CustomSnmp(ISnmpLog snmpLog, ILogger<CustomSnmp> logger)
        {
            _SnmpLog = snmpLog ?? throw new ArgumentNullException(nameof(snmpLog));
            _Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<(int bulkwalkResult, IList<Variable> results)> GetSubtreeV2Async(IPAddress ip, string oid, string community, int port, int? maxRepetitions,
            int? retries, TimeSpan? timeout)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (string.IsNullOrWhiteSpace(community))
            {
                throw new ArgumentNullException(nameof(community));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            var maxRepetitionsValue = maxRepetitions ?? 10;
            if (maxRepetitionsValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), maxRepetitions.ToString());
            }

            var retriesValue = retries ?? 2;
            if (retriesValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            var timeoutMs = timeout ?? TimeSpan.FromSeconds(5);
            if (timeoutMs <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            var results = new List<Variable>();
            var bulkwalkResult = await MyMessenger.BulkWalkV2Async(
                new IPEndPoint(ip, port),
                community == null ? OctetString.Empty : new OctetString(community),
                new ObjectIdentifier(oid),
                results,
                maxRepetitionsValue,
                retriesValue,
                timeoutMs,
                WalkMode.WithinSubtree
                ).ConfigureAwait(false);

            return (bulkwalkResult, results);
        }

        [Obsolete("SHA1 and DES are insecure")]
        public async Task<(int bulkwalkResult, IList<Variable> results)> GetSubtreeV3UsmAsync(IPAddress ip, string oid, string community, int port, int? maxRepetitions,
            int? retries, TimeSpan? timeout, string authPassword, string privPassword)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            var maxRepetitionsValue = maxRepetitions ?? 10;
            if (maxRepetitionsValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), maxRepetitions.ToString());
            }

            var retriesValue = retries ?? 2;
            if (retriesValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            var timeoutMs = timeout ?? TimeSpan.FromSeconds(5);
            if (timeoutMs <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            if (string.IsNullOrWhiteSpace(authPassword))
            {
                throw new ArgumentNullException(nameof(authPassword));
            }

            if (string.IsNullOrWhiteSpace(privPassword))
            {
                throw new ArgumentNullException(nameof(privPassword));
            }

            var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
            var report = await discovery.GetResponseAsync(new IPEndPoint(ip, 161)).ConfigureAwait(false);
            var auth = new SHA1AuthenticationProvider(new OctetString(authPassword)); // AuthenticationPassword
            var priv = new DESPrivacyProvider(new OctetString(privPassword), auth); //PrivacyPassword

            var results = new List<Variable>();
            var bulkwalkResult = await MyMessenger.BulkWalkV3UsmAsync(
                new IPEndPoint(ip, port),
                community == null ? OctetString.Empty : new OctetString(community),
                new ObjectIdentifier(oid),
                results,
                maxRepetitionsValue,
                retriesValue,
                timeoutMs,
                WalkMode.WithinSubtree,
                priv,
                report
                ).ConfigureAwait(false);

            return (bulkwalkResult, results);
        }

        public async Task<(int bulkwalkResult, IList<Variable> results)> GetSubtreeV3TsmAsync(IPAddress ip, string oid, int port, int? maxRepetitions,
            int? retries, TimeSpan? timeout, X509Certificate2 certificate, TimeSpan? connectionTimeout)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            var maxRepetitionsValue = maxRepetitions ?? 10;
            if (maxRepetitionsValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRepetitions), maxRepetitions.ToString());
            }

            var retriesValue = retries ?? 2;
            if (retriesValue <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            var timeoutMs = timeout ?? TimeSpan.FromSeconds(5);
            if (timeoutMs <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            var connTimeout = connectionTimeout ?? TimeSpan.FromSeconds(2);
            if (connTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(connectionTimeout));
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var auth = TsmAuthenticationProvider.Instance;
            var priv = new TsmPrivacyProvider(auth);

            var results = new List<Variable>();
            var bulkwalkResult = await MyMessenger.BulkWalkV3TsmAsync(
                new IPEndPoint(ip, port),
                new ObjectIdentifier(oid),
                results,
                maxRepetitionsValue,
                retriesValue,
                timeoutMs,
                WalkMode.WithinSubtree,
                priv,
                null,
                certificate,
                connTimeout
                ).ConfigureAwait(false);

            return (bulkwalkResult, results);
        }

        public async Task<Variable?> GetV2Async(IPAddress ip, string oid, string community, int retries, int port, TimeSpan timeout)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            var startDate = DateTime.Now;
            var snmpType = "GET";
            var snmpVersion = "2c";

            var attempt = 0;
            IEnumerable<Variable> result = new List<Variable>();
            while (attempt < retries)
            {
                try
                {
                    result = await MyMessenger.GetAsync(VersionCode.V2,
                        new IPEndPoint(ip, port),
                        new OctetString(community),
                        new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                        timeout
                        ).ConfigureAwait(false);

                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException)
                {
                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);
                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }
            }

            var type = string.Empty;
            var data = string.Empty;
            foreach (var res in result)
            {
                type += res.Data.TypeCode;
                data += res.Data.ToString();
            }

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, type, data).ConfigureAwait(false);

            return result.FirstOrDefault();
        }

        //Needs Tested
        [Obsolete("SHA1 and DES are insecure")]
        public async Task<Variable?> GetV3UsmAsync(IPAddress ip, string oid, string community, int retries, int port, TimeSpan timeout,
            string authPass, string privPass)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            if (string.IsNullOrWhiteSpace(authPass))
            {
                throw new ArgumentNullException(nameof(authPass));
            }

            if (string.IsNullOrWhiteSpace(privPass))
            {
                throw new ArgumentNullException(nameof(privPass));
            }

            var startDate = DateTime.Now;
            var snmpType = "GET";
            var snmpVersion = $"3 {SecurityModel.Usm}";

            var attempt = 0;
            IEnumerable<Variable> reply = new List<Variable>();
            while (attempt < retries)
            {
                try
                {
                    var receiver = new IPEndPoint(ip, port);
                    var clientEndPoint = ip.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    var vList = new List<Variable>() { new Variable(new ObjectIdentifier(oid)) };

                    using var cts = new CancellationTokenSource(timeout);
                    var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                    var report = await discovery.GetResponseAsync(receiver).ConfigureAwait(false);
                    var auth = new SHA1AuthenticationProvider(new OctetString(authPass)); // AuthenticationPassword
                    var priv = new DESPrivacyProvider(new OctetString(privPass), auth); //PrivacyPassword
                    var request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(community), vList, priv, Messenger.MaxMessageSize, report);
                    ISnmpMessage response = await request.GetResponseAsync(receiver, cts.Token).ConfigureAwait(false);

                    if (response is ReportMessage)
                    {
                        if (response.Pdu().Variables.Count == 0)
                        {
                            throw new Exception("wrong report message received");
                        }

                        var id = response.Pdu().Variables[0].Id;
                        if (id != Messenger.NotInTimeWindow)
                        {
                            var error = id.GetErrorMessage();
                            throw new Exception($"ERROR: {error}");
                        }
                    }
                    else if (response.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            response);
                    }

                    reply = response.Pdu().Variables;
                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    if (ex is System.TimeoutException && ex.Message == "Could Not Connect To Server")
                    {
                        _Logger.LogInformation($"{ip} - DTLS failed {attempt + 1} time(s)");
                    }

                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);

                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }
            }

            var type = string.Empty;
            var data = string.Empty;
            foreach (var res in reply)
            {
                type += res.Data.TypeCode;
                data += res.Data.ToString();
            }

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, type, data).ConfigureAwait(false);

            return reply.FirstOrDefault();
        }

        public async Task<Variable?> GetV3TsmAsync(IPAddress ip, string oid, int retries, int port, TimeSpan timeout,
            X509Certificate2 certificate, TimeSpan connectionTimeout)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            if (connectionTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(connectionTimeout));
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var startDate = DateTime.Now;
            var snmpType = "GET";
            var snmpVersion = $"3 {SecurityModel.Tsm}";

            var attempt = 0;
            IEnumerable<Variable> reply = new List<Variable>();
            while (attempt < retries)
            {
                try
                {
                    var receiver = new IPEndPoint(ip, port);
                    var clientEndPoint = ip.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    var vList = new List<Variable>() { new Variable(new ObjectIdentifier(oid)) };

                    var chain = new X509Chain();
                    chain.Build(certificate);

                    using var client = new Client(clientEndPoint);
                    client.LoadX509Certificate(chain);
                    client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);

                    var auth = TsmAuthenticationProvider.Instance;
                    IPrivacyProvider priv = new TsmPrivacyProvider(auth);

                    var request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, OctetString.Empty, vList, priv, Messenger.MaxMessageSize);
                    ISnmpMessage response = await request.GetSecureResponseAsync(connectionTimeout, timeout, receiver, client).ConfigureAwait(false);

                    if (response is ReportMessage)
                    {
                        if (response.Pdu().Variables.Count == 0)
                        {
                            throw new Exception("wrong report message received");
                        }

                        var id = response.Pdu().Variables[0].Id;
                        if (id != Messenger.NotInTimeWindow)
                        {
                            var error = id.GetErrorMessage();
                            throw new Exception($"ERROR: {error}");
                        }

                        // according to RFC 3414, send a second request to sync time.
                        var request2 = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, OctetString.Empty, OctetString.Empty, vList, priv, Messenger.MaxMessageSize, response);
                        response = await request2.GetSecureResponseAsync(connectionTimeout, timeout, receiver, client).ConfigureAwait(false);
                    }
                    else if (response.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            response);
                    }

                    reply = response.Pdu().Variables;
                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    if (ex is System.TimeoutException && ex.Message == "Could Not Connect To Server")
                    {
                        _Logger.LogInformation($"{ip} - DTLS failed {attempt + 1} time(s)");
                    }

                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);

                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }
            }

            var type = string.Empty;
            var data = string.Empty;
            foreach (var res in reply)
            {
                type += res.Data.TypeCode;
                data += res.Data.ToString();
            }

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, type, data).ConfigureAwait(false);

            return reply.FirstOrDefault();
        }

        public async Task<ISnmpMessage?> SetV2Async<T>(IPAddress ip, string oid, string community, int retries, int port, TimeSpan timeout, T setValue)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (string.IsNullOrWhiteSpace(community))
            {
                throw new ArgumentNullException(nameof(community));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            var startDate = DateTime.Now;
            var snmpType = "SET";
            var snmpVersion = "2c";

            var attempt = 0;
            ISnmpMessage? response = null;
            while (attempt < retries)
            {
                var setValueByType = setValue switch
                {
                    int x => new Variable(new ObjectIdentifier(oid), new Integer32(x)),
                    string x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    IPAddress x => new Variable(new ObjectIdentifier(oid), new IP(x.ToString())),
                    uint x => new Variable(new ObjectIdentifier(oid), new Gauge32(x)),
                    byte[] x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    _ => throw new ArgumentOutOfRangeException(nameof(setValue)),
                };

                try
                {
                    var receiver = new IPEndPoint(ip, port);
                    var request = new SetRequestMessage(Messenger.NextMessageId, VersionCode.V2, new OctetString(community),
                               new List<Variable> { setValueByType });

                    using var cts = new CancellationTokenSource(timeout);
                    response = await request.GetResponseAsync(receiver, cts.Token).ConfigureAwait(false);

                    if (response is ReportMessage)
                    {
                        if (response.Pdu().Variables.Count == 0)
                        {
                            throw new Exception("wrong report message received");
                        }

                        var id = response.Pdu().Variables[0].Id;
                        if (id != Messenger.NotInTimeWindow)
                        {
                            var error = id.GetErrorMessage();
                            throw new Exception($"ERROR: {error}");
                        }
                    }

                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException)
                {
                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);
                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }

            }

            if (response is null)
            {
                await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, SnmpType.Null.ToString(), null).ConfigureAwait(false);
                return response;
            }

            var type = response.Pdu().TypeCode;
            var data = response.Pdu().ErrorStatus;

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, type.ToString(), data.ToString()).ConfigureAwait(false);
            return response;
        }

        //This part has not been tested. We need a USM setup to test
        [Obsolete("SHA1 and DES are insecure")]
        public async Task<ISnmpMessage?> SetV3UsmAsync<T>(IPAddress ip, string oid, string community, int retries, int port, TimeSpan timeout,
            string authPass, string privPass, T setValue)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (string.IsNullOrWhiteSpace(community))
            {
                throw new ArgumentNullException(nameof(community));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            var startDate = DateTime.Now;
            var snmpType = "SET";
            var snmpVersion = $"3 {SecurityModel.Usm}";

            var attempt = 0;
            ISnmpMessage? response = null;
            while (attempt < retries)
            {
                var setValueByType = setValue switch
                {
                    int x => new Variable(new ObjectIdentifier(oid), new Integer32(x)),
                    string x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    IPAddress x => new Variable(new ObjectIdentifier(oid), new IP(x.ToString())),
                    uint x => new Variable(new ObjectIdentifier(oid), new Gauge32(x)),
                    byte[] x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    _ => throw new ArgumentOutOfRangeException(nameof(setValue)),
                };

                try
                {
                    var receiver = new IPEndPoint(ip, port);
                    var clientEndPoint = ip.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    var vList = new List<Variable>() { setValueByType };

                    var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                    var report = await discovery.GetResponseAsync(receiver).ConfigureAwait(false);
                    var auth = new SHA1AuthenticationProvider(new OctetString(authPass)); // AuthenticationPassword
                    var priv = new DESPrivacyProvider(new OctetString(privPass), auth); //PrivacyPassword
                    var request = new SetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(community), vList, priv, report);

                    using var cts = new CancellationTokenSource(timeout);
                    response = await request.GetResponseAsync(receiver, cts.Token).ConfigureAwait(false);

                    if (response is ReportMessage)
                    {
                        if (response.Pdu().Variables.Count == 0)
                        {
                            throw new Exception("wrong report message received");
                        }

                        var id = response.Pdu().Variables[0].Id;
                        if (id != Messenger.NotInTimeWindow)
                        {
                            var error = id.GetErrorMessage();
                            throw new Exception($"ERROR: {error}");
                        }
                    }

                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    if (ex is System.TimeoutException && ex.Message == "Could Not Connect To Server")
                    {
                        _Logger.LogInformation($"{ip} - DTLS failed {attempt + 1} time(s)");
                    }

                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);
                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }
            }

            if (response is null)
            {
                await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, SnmpType.Null.ToString(), null).ConfigureAwait(false);
                return response;
            }

            var type = response.Pdu().TypeCode;
            var data = response.Pdu().ErrorStatus;

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, community, snmpType, snmpVersion, type.ToString(), data.ToString()).ConfigureAwait(false);
            return response;
        }

        public async Task<ISnmpMessage?> SetV3TsmAsync<T>(IPAddress ip, string oid, int retries, int port, TimeSpan timeout,
            X509Certificate2 certificate, TimeSpan connectionTimeout, T setValue)
        {
            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (string.IsNullOrWhiteSpace(oid))
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Regex.IsMatch(oid, @"^(([0-9]+)\.)+[0-9]+$"))
            {
                throw new ArgumentException(oid, nameof(oid));
            }

            if (port <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(port), port.ToString());
            }

            if (retries <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(retries), retries.ToString());
            }

            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout), timeout.ToString());
            }

            if (connectionTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(connectionTimeout));
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var startDate = DateTime.Now;
            var snmpType = "SET";
            var snmpVersion = $"3 {SecurityModel.Tsm}";

            var attempt = 0;
            ISnmpMessage? response = null;
            while (attempt < retries)
            {
                var setValueByType = setValue switch
                {
                    int x => new Variable(new ObjectIdentifier(oid), new Integer32(x)),
                    string x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    IPAddress x => new Variable(new ObjectIdentifier(oid), new IP(x.ToString())),
                    uint x => new Variable(new ObjectIdentifier(oid), new Gauge32(x)),
                    byte[] x => new Variable(new ObjectIdentifier(oid), new OctetString(x)),
                    _ => throw new ArgumentOutOfRangeException(nameof(setValue)),
                };

                try
                {
                    var receiver = new IPEndPoint(ip, port);
                    var clientEndPoint = ip.AddressFamily == AddressFamily.InterNetwork
                        ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
                    var vList = new List<Variable>() { setValueByType };

                    var chain = new X509Chain();
                    chain.Build(certificate);

                    using var client = new Client(clientEndPoint);
                    client.LoadX509Certificate(chain);
                    client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);

                    var auth = TsmAuthenticationProvider.Instance;
                    IPrivacyProvider priv = new TsmPrivacyProvider(auth);

                    var request = new SetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, OctetString.Empty, vList, priv, Messenger.MaxMessageSize);
                    response = await request.GetSecureResponseAsync(connectionTimeout, timeout, receiver, client).ConfigureAwait(false);

                    if (response is ReportMessage)
                    {
                        if (response.Pdu().Variables.Count == 0)
                        {
                            throw new Exception("wrong report message received");
                        }

                        var id = response.Pdu().Variables[0].Id;
                        if (id != Messenger.NotInTimeWindow)
                        {
                            var error = id.GetErrorMessage();
                            throw new Exception($"ERROR: {error}");
                        }

                        var request2 = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, OctetString.Empty, OctetString.Empty, vList, priv, Messenger.MaxMessageSize, response);
                        response = await request2.GetSecureResponseAsync(connectionTimeout, timeout, receiver, client).ConfigureAwait(false);
                    }

                    break;
                }
                catch (Exception ex) when (ex is SnmpException || ex is SocketException || ex is OperationCanceledException || ex is System.TimeoutException)
                {
                    if (ex is System.TimeoutException && ex.Message == "Could Not Connect To Server")
                    {
                        _Logger.LogInformation($"{ip} - DTLS failed {attempt + 1} time(s)");
                    }

                    await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, ex.GetType().ToString(), ex.Message).ConfigureAwait(false);
                    ++attempt;
                    if (attempt >= retries)
                    {
                        throw;
                    }
                }
            }

            if (response is null)
            {
                await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, SnmpType.Null.ToString(), null).ConfigureAwait(false);
                return response;
            }

            var type = response.Pdu().TypeCode;
            var data = response.Pdu().ErrorStatus;

            await _SnmpLog.LogTransactionAsync(startDate, ip.ToString(), oid, null, snmpType, snmpVersion, type.ToString(), data.ToString()).ConfigureAwait(false);
            return response;
        }
    }
}
