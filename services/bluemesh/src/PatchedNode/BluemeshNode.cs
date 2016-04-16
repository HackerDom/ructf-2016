using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Data;
using Node.Encryption;
using Node.Messages;
using Node.Routing;

namespace PatchedNode
{
    internal class BluemeshNode
    {
        public BluemeshNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager, bool doLogMap)
        {
            this.routingManager = routingManager;
            this.connectionManager = connectionManager;
            this.dataManager = dataManager;
            this.encryptionManager = encryptionManager;
            this.doLogMap = doLogMap;
        }

        public void Start()
        {
            encryptionManager.GenerateKeyPair(BitConverter.GetBytes(connectionManager.Address.GetHashCode()));
            encryptionManager.Start();
            while (true)
            {
                lock (dataManager)
                    Tick();
                Thread.Sleep(TimeSpan.FromMilliseconds(10));
            }
        }

        public void PutFlag(string key, string flag, IAddress destination)
        {
            lock (dataManager)
                dataManager.DispatchData(key, Encoding.UTF8.GetBytes(flag), destination);
        }

        public string GetFlag(string key, IAddress source, TimeSpan timeout)
        {
            var trigger = new ManualResetEventSlim();
            string flag = null;
            Action<DataMessage> action = m =>
            {
                if (m.Action == DataAction.None && m.Key == key)
                {
                    flag = Encoding.UTF8.GetString(m.Data);
                    trigger.Set();
                }
            };
            dataManager.OnReceivedData += action;
            try
            {
                lock (dataManager)
                    dataManager.RequestData(key, source);
                trigger.Wait(timeout);

                return flag;
            }
            finally
            {
                dataManager.OnReceivedData -= action;
            }
        }
        public ICollection<RoutingMapLink> Map { get; private set; }

        private void Tick()
        {
            connectionManager.PurgeDeadConnections();
            var selectResult = connectionManager.Select();

            routingManager.UpdateConnections();

            foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
            {
                for (int i = 0; i < 3 && connection.Socket.Available > 0; i++)
                {
                    var message = connection.Receive();
                    if (!routingManager.ProcessMessage(message, connection))
                        dataManager.ProcessMessage(message, connection);
                }
            }
            routingManager.PushMaps(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));
            dataManager.PushMessages(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));

            routingManager.DisconnectExcessLinks();
            routingManager.ConnectNewLinks();

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

            if (doLogMap)
                Console.WriteLine("[{0}] v: {2} {1}", routingManager.Map.OwnAddress, routingManager.Map, routingManager.Map.Version);
            //if (dataManager.DataStorage.ToString().Length > 0)
            //    Console.WriteLine("[{0}] !! my flags : {1}", routingManager.Map.OwnAddress, dataManager.DataStorage);
            Map = routingManager.Map.Links.ToList();
        }

        private readonly RoutingManager routingManager;
        private readonly TcpConnectionManager connectionManager;
        private readonly DataManager dataManager;
        private readonly EncryptionManager encryptionManager;
        private readonly bool doLogMap;
    }
}