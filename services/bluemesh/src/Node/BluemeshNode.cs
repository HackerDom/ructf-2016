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

namespace Node
{
    internal class BluemeshNode
    {
        public BluemeshNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager, bool doLogMap)
        {
            this.RoutingManager = routingManager;
            this.ConnectionManager = connectionManager;
            this.DataManager = dataManager;
            this.EncryptionManager = encryptionManager;
            this.DoLogMap = doLogMap;
        }

        public virtual void Start()
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

        public virtual void PutFlag(string key, string flag, IAddress destination)
        {
            lock (DataManager)
                DataManager.DispatchData(key, Encoding.UTF8.GetBytes(flag), destination);
        }

        public virtual string GetFlag(string key, IAddress source, TimeSpan timeout)
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
            DataManager.OnReceivedData += action;
            try
            {
                lock (DataManager)
                    DataManager.RequestData(key, source);
                trigger.Wait(timeout);

                return flag;
            }
            finally
            {
                DataManager.OnReceivedData -= action;
            }
        }
        public ICollection<RoutingMapLink> Map { get; protected set; }

        protected virtual void Tick()
        {
            ConnectionManager.PurgeDeadConnections();
            var selectResult = ConnectionManager.Select();

            RoutingManager.UpdateConnections();
            EncryptionManager.RetrievePeerKeys(ConnectionManager.EstablishedConnections.Select(c => c.RemoteAddress));

            foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
            {
                for (int i = 0; i < 3 && connection.Socket.Available > 0; i++)
                {
                    var message = connection.Receive();
                    if (!RoutingManager.ProcessMessage(message, connection))
                        DataManager.ProcessMessage(message, connection);
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
            Map = RoutingManager.Map.Links.ToList();
        }

        protected readonly RoutingManager RoutingManager;
        protected readonly TcpConnectionManager ConnectionManager;
        protected readonly DataManager DataManager;
        protected readonly EncryptionManager EncryptionManager;
        protected readonly bool DoLogMap;
    }
}