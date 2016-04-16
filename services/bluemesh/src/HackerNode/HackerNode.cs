using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using Node;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Data;
using Node.Encryption;
using Node.Messages;
using Node.Routing;

namespace HackerNode
{
    internal class HackerNode : BluemeshNode
    {
        public HackerNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager, bool doLogMap)
            : base(routingManager, connectionManager, dataManager, encryptionManager, doLogMap)
        {
        }

        public override void Start()
        {
            EncryptionManager.GenerateKeyPair(BitConverter.GetBytes(new Random().Next()));
            EncryptionManager.Start();
            while (true)
            {
                try
                {
                    lock (DataManager)
                        Tick();
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: " + e);
                }
                Thread.Sleep(TimeSpan.FromMilliseconds(10));
            }
        }

        protected override void Tick()
        {
            ConnectionManager.PurgeDeadConnections();
            var selectResult = ConnectionManager.Select();

            RoutingManager.UpdateConnections();

            foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
            {
                for (int i = 0; i < 3 && connection.Socket.Available > 0; i++)
                {
                    var message = connection.Receive();
                    if (!RoutingManager.ProcessMessage(message, connection))
                    {
                        DataManager.ProcessMessage(message, connection);
                        HackMessage(message);
                    }
                }
            }
            RoutingManager.PushMaps(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));
            DataManager.PushMessages(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));

            RoutingManager.DisconnectExcessLinks();
            RoutingManager.ConnectNewLinks();

            foreach (var connection in selectResult.ReadableConnections)
            {
                //Console.WriteLine("[{0}] tick: {1} -> {2}", connectionManager.Address, connectionManager.Address, connection.RemoteAddress);
                connection.Tick(true);
            }
            foreach (var connection in selectResult.WritableConnections)
            {
                //Console.WriteLine("[{0}] tick: {1} -> {2}", connectionManager.Address, connectionManager.Address, connection.RemoteAddress);
                connection.Tick(false);
            }

            if (DoLogMap)
                Console.WriteLine("[{0}] v: {2} {1}", RoutingManager.Map.OwnAddress, RoutingManager.Map, RoutingManager.Map.Version);
            //if (dataManager.DataStorage.ToString().Length > 0)
            //    Console.WriteLine("[{0}] !! my flags : {1}", routingManager.Map.OwnAddress, dataManager.DataStorage);
        }

        private void HackMessage(IMessage message)
        {
            var redirectMessage = message as RedirectMessage;
            if (redirectMessage == null)
                return;
            while (true)
            {
                var keys = (Dictionary<IPEndPoint, ulong>) EncryptionManager.GetType()
                    .GetField("peerKeys", BindingFlags.Instance | BindingFlags.NonPublic)
                    .GetValue(EncryptionManager);
                var publicKey = keys[((TcpAddress) redirectMessage.Destination).Endpoint];
                var privateKey = BluemeshEncryptor.GeneratePublicKey(publicKey);
                var bytes = redirectMessage.Data.ToArray();
                BluemeshEncryptor.EncryptBytes(bytes, MessageContainer.HeaderSize, bytes.Length - MessageContainer.HeaderSize, privateKey);
                var newMessage = MessageContainer.ReadFromBuffer(bytes, 0, ConnectionManager.Utility).Message;
                if (newMessage is DataMessage)
                {
                    Console.WriteLine("FLAG: " + Encoding.UTF8.GetString(((DataMessage)newMessage).Data));
                    break;
                }
                redirectMessage = (RedirectMessage)newMessage;
            }
        }
    }
}