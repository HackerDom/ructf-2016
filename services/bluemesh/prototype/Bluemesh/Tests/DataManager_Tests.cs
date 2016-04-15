using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Data;
using Node.Encryption;
using Node.Messages;
using Node.Routing;
using NSubstitute;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class DataManager_Tests
    {
        [Test, Explicit, Timeout(30000)]
        public void Measure_put_get()
        {
            //Console.SetOut(new StreamWriter("map-negotiation.log"));

            var config = Substitute.For<IRoutingConfig>();
            config.DesiredConnections.Returns(3);
            config.MaxConnections.Returns(3);
            config.ConnectCooldown.Returns(100.Milliseconds());
            config.DisconnectCooldown.Returns(100.Milliseconds());
            config.MapUpdateCooldown.Returns(20.Milliseconds());
            var preconfiguredNodes = new List<IAddress>();
            var nodes = Enumerable.Range(0, 15).Select(i => CreateNode(config, preconfiguredNodes, i)).ToList();

            ThreadPool.SetMinThreads(nodes.Count * 2, nodes.Count * 2);

            var trigger = new ManualResetEventSlim();
            var tasks = nodes.Select(n => Task.Run(() =>
            {
                trigger.Wait();
                n.Start();
            })).ToList();

            var watch = Stopwatch.StartNew();
            trigger.Set();

            Task.Delay(2.Seconds()).Wait();

            Console.WriteLine("!!! Put flag");
            nodes[0].PutFlag("test1", "hujhujhuj", nodes.Last().Address);
            Console.WriteLine("!!! Get flag");
            var flag = nodes[0].GetFlag("test1", nodes.Last().Address);
            Console.WriteLine("!!! Flag : " + flag);

            flag.Should().Be("hujhujhuj");
            foreach (var node in nodes)
                node.Stopped = true;

            Task.WhenAll(tasks).Wait();

            Console.WriteLine("Communication took " + watch.Elapsed);
        }

        private static TestNode CreateNode(IRoutingConfig routingConfig, List<IAddress> nodes, int id)
        {
            var connectionConfig = Substitute.For<IConnectionConfig>();
            var address = new TcpAddress(new IPEndPoint(IPAddress.Loopback, 16800 + id));
            connectionConfig.LocalAddress.Returns(address);
            connectionConfig.PreconfiguredNodes.Returns(_ => nodes.Where(n => !Equals(n, address)).ToList());
            nodes.Add(address);
            connectionConfig.ConnectingSocketMaxTTL.Returns(TimeSpan.FromMilliseconds(50));
            connectionConfig.ConnectingSocketsToConnectionsMultiplier.Returns(5);
            connectionConfig.KeySendCooldown.Returns(TimeSpan.FromMilliseconds(1000));
            var encryptionManager = new EncryptionManager(address.Endpoint, connectionConfig.KeySendCooldown);
            var connectionManager = new TcpConnectionManager(connectionConfig, routingConfig, encryptionManager);
            var routingManager = new RoutingManager(connectionManager, routingConfig);
            var dataManager = new DataManager(new DataStorage(), "", routingManager, encryptionManager);
            return new TestNode(routingManager, connectionManager, dataManager, encryptionManager);
        }

        private class TestNode
        {
            public TestNode(RoutingManager routingManager, TcpConnectionManager connectionManager, DataManager dataManager, EncryptionManager encryptionManager)
            {
                this.routingManager = routingManager;
                this.connectionManager = connectionManager;
                this.dataManager = dataManager;
                this.encryptionManager = encryptionManager;
            }

            public void Start()
            {
                encryptionManager.GenerateKeyPair(BitConverter.GetBytes(connectionManager.Address.GetHashCode()));
                encryptionManager.Start();
                while (!Stopped)
                {
                    Tick();
                    Thread.Sleep(10.Milliseconds());
                }
                connectionManager.Stop();
                encryptionManager.Stop();
                Console.WriteLine("Stopped node {0}", connectionManager.Address);
            }

            public bool Stopped { get; set; }

            public void PutFlag(string key, string flag, IAddress destination)
            {
                dataManager.DispatchData(key, Encoding.UTF8.GetBytes(flag), destination);
            }

            public string GetFlag(string key, IAddress source)
            {
                var trigger = new ManualResetEventSlim();
                string flag = null;
                dataManager.OnReceivedData += m =>
                {
                    if (m.Action == DataAction.None && m.Key == key)
                    {
                        flag = Encoding.UTF8.GetString(m.Data);
                        trigger.Set();
                    }
                };
                dataManager.RequestData(key, source);
                trigger.Wait();
                return flag;
            }

            private void Tick()
            {
                connectionManager.PurgeDeadConnections();
                var selectResult = connectionManager.Select();

                routingManager.UpdateConnections();

                foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
                {
                    var message = connection.Receive();
                    if (!routingManager.ProcessMessage(message, connection))
                        dataManager.ProcessMessage(message, connection);
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

                //Console.WriteLine("[{0}] v: {2} {1}", routingManager.Map.OwnAddress, routingManager.Map, routingManager.Map.Version);
                if (dataManager.DataStorage.ToString().Length > 0)
                    Console.WriteLine("[{0}] !! my flags : {1}", routingManager.Map.OwnAddress, dataManager.DataStorage);
            }

            public IAddress Address => connectionManager.Address;

            private readonly RoutingManager routingManager;
            private readonly TcpConnectionManager connectionManager;
            private readonly DataManager dataManager;
            private readonly EncryptionManager encryptionManager;
        }
    }
}