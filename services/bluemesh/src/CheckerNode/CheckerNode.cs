using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Node;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Data;
using Node.Encryption;
using Node.Messages;
using Node.Routing;

namespace CheckerNode
{
    internal class CheckerNode : BluemeshNode
    {
        public CheckerNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager, bool doLogMap)
            : base(routingManager, connectionManager, dataManager, encryptionManager, doLogMap)
        {
        }

        protected override void Tick()
        {
            base.Tick();

            if (DataManager.DataStorage.ToString().Length > 0)
                Console.WriteLine("[{0}] !! my flags : {1}", RoutingManager.Map.OwnAddress, DataManager.DataStorage);

            Console.WriteLine("[{0}] !! conns : {1}", RoutingManager.Map.OwnAddress, 
                string.Join(", ", ConnectionManager.EstablishedConnections.Select(c => RoutingManager.Map.OwnAddress + " <-> " + c.RemoteAddress)));

            Action result;
            while (scheduledActions.TryDequeue(out result))
                result();
        }

        public void Connect(IAddress address)
        {
            scheduledActions.Enqueue(() => ConnectionManager.TryConnect(address));
        }

        public void Disconnect(IAddress address)
        {
            scheduledActions.Enqueue(() =>
            {
                var conn = ConnectionManager.EstablishedConnections.FirstOrDefault(c => Equals(c.RemoteAddress, address));
                conn?.Close();
            });
        }

        private readonly ConcurrentQueue<Action> scheduledActions = new ConcurrentQueue<Action>();
    }
}