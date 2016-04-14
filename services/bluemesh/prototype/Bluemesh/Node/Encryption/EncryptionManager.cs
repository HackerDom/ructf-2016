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
        }

        public void Start()
        {
            listenerThread = new Thread(Listen);
            listenerThread.Start();
        }

        public void Stop()
        {
            stopped = true;
        }

        public void RetrievePeerKeys(IEnumerable<IAddress> peers)
        {
            foreach (var address in peers.OfType<TcpAddress>())
            {
                TryDownloadKey(address.Endpoint);
            }
        }

        public IMessageEncoder CreateEncoder(IAddress peer)
        {
            var tcpAddress = peer as TcpAddress;
            ulong key;
            lock (peerKeys)
            {
                if (tcpAddress == null || !peerKeys.TryGetValue(tcpAddress.Endpoint, out key))
                {
                    Console.WriteLine("No public key for address {0}", peer);
                    return new MessageEncoder(privateKey, 0);
                }
            }
            return new MessageEncoder(privateKey, key);
        }

        private void Listen()
        {
            listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            listenerSocket.Bind(serverEndpoint);
            while (!stopped)
            {
                EndPoint endpoint = null;
                if (listenerSocket.ReceiveFrom(keyBuffer, ref endpoint) == 8)
                {
                    var key = BitConverter.ToUInt64(keyBuffer, 0);
                    lock (peerKeys)
                        peerKeys[(IPEndPoint) endpoint] = key;
                    Console.WriteLine("KeyManager: {0} has {1}", endpoint, key);
                }
            }
            listenerSocket.Close();
        }

        private void TryDownloadKey(IPEndPoint endpoint)
        {
            DateTime lastSendTime;
            if (lastSend.TryGetValue(endpoint, out lastSendTime) && DateTime.UtcNow - lastSendTime <= sendCooldown)
                return;

            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.SendTo(BitConverter.GetBytes(publicKey), endpoint);

            lastSend[endpoint] = DateTime.UtcNow;
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