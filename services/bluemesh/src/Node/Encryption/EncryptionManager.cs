using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Node.Connections;
using Node.Connections.Tcp;

namespace Node.Encryption
{
    internal class EncryptionManager : IEncryptionManager
    {
        public EncryptionManager(IPEndPoint serverEndpoint, TimeSpan sendCooldown)
        {
            this.serverEndpoint = serverEndpoint;
            this.sendCooldown = sendCooldown;
            peerKeys = new Dictionary<IPEndPoint, ulong>();
            lastSend = new Dictionary<IPEndPoint, DateTime>();
        }

        public void GenerateKeyPair(byte[] seed)
        {
            privateKey = BluemeshEncryptor.GeneratePrivateKey(seed);
            publicKey = BluemeshEncryptor.GeneratePublicKey(privateKey);
            lock (peerKeys)
                peerKeys[serverEndpoint] = publicKey;
        }

        public void Start()
        {
            listenerThread = new Thread(Listen);
            listenerThread.Start();
        }

        public void Stop()
        {
            stopped = true;
            listenerThread.Abort();
        }

        public void RetrievePeerKeys(IEnumerable<IAddress> peers)
        {
            foreach (var address in peers.OfType<TcpAddress>())
            {
                TryDownloadKey(address.Endpoint);
            }
        }

        public IMessageEncoder CreateEncoder(IConnection connection)
        {
            return new MessageEncoder(privateKey, () => GetPublicKey(connection.RemoteAddress));
        }

        private ulong GetPublicKey(IAddress address)
        {
            lock (peerKeys)
            {
                ulong key;
                var tcpAddress = address as TcpAddress;
                if (tcpAddress == null || !peerKeys.TryGetValue(tcpAddress.Endpoint, out key))
                {
                    Console.WriteLine("No public key for address {0}", tcpAddress);
                    return 0UL;
                }
                return key;
            }
        }

        public void EncryptData(byte[] data, int offset, int length, IAddress peer)
        {
            BluemeshEncryptor.EncryptBytes(data, offset, length % 8 == 0 ? length : length + (8 - length % 8), GetPublicKey(peer));
        }

        public void DecryptData(byte[] data, int offset, int length)
        {
            BluemeshEncryptor.EncryptBytes(data, offset, length % 8 == 0 ? length : length + (8 - length % 8), privateKey);
        }

        private void Listen()
        {
            //Console.WriteLine("Listening on {0}", serverEndpoint);
            listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            listenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listenerSocket.Bind(serverEndpoint);
            while (!stopped)
            {
                EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                if (listenerSocket.ReceiveFrom(keyBuffer, ref endpoint) == 8)
                {
                    var key = BitConverter.ToUInt64(keyBuffer, 0);
                    Console.WriteLine("KeyManager: {0} has {1}", endpoint, key);
                    lock (peerKeys)
                        peerKeys[(IPEndPoint) endpoint] = key;
                }
            }
            listenerSocket.Close();
        }

        private void TryDownloadKey(IPEndPoint endpoint)
        {
            DateTime lastSendTime;
            if (lastSend.TryGetValue(endpoint, out lastSendTime) && DateTime.UtcNow - lastSendTime <= sendCooldown)
                return;

            try
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                {
                    Blocking = false
                };
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.Bind(serverEndpoint);
                socket.SendTo(BitConverter.GetBytes(publicKey), endpoint);
                lastSend[endpoint] = DateTime.UtcNow;
            }
            catch (Exception e)
            {
                Console.WriteLine("TryDownloadKey : " + e.Message);
            }
        }

        private bool stopped;

        private Thread listenerThread;
        private Socket listenerSocket;

        private readonly byte[] keyBuffer = new byte[8];

        private ulong privateKey;
        private ulong publicKey;

        private readonly Dictionary<IPEndPoint, ulong> peerKeys;
        private readonly Dictionary<IPEndPoint, DateTime> lastSend;
        private readonly IPEndPoint serverEndpoint;
        private readonly TimeSpan sendCooldown;
    }
}