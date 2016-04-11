using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Node.Connections;
using Node.Connections.Tcp;
using Node.Messages;
using Node.Routing;
using NSubstitute;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class RoutingManager_Tests
    {
        [Test, Explicit, Timeout(3000)]
        public void Measure_map_negotiation()
        {
            var config = Substitute.For<IRoutingConfig>();
            config.DesiredConnections.Returns(1);
            config.MaxConnections.Returns(1);
            var preconfiguredNodes = new List<IAddress>();
            var nodes = Enumerable.Range(0, 2).Select(i => CreateNode(config, preconfiguredNodes, i)).ToList();

            ThreadPool.SetMinThreads(nodes.Count * 2, nodes.Count * 2);

            var trigger = new ManualResetEventSlim();
            var tasks = nodes.Select(n => Task.Run(() =>
            {
                trigger.Wait();
                n.Start();
            })).ToList();

            var watch = Stopwatch.StartNew();
            trigger.Set();
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
            var connectionManager = new TcpConnectionManager(connectionConfig, routingConfig);
            return new TestNode(new RoutingManager(connectionManager, routingConfig), connectionManager);
        }

        private class TestNode
        {
            public TestNode(RoutingManager routingManager, TcpConnectionManager connectionManager)
            {
                this.routingManager = routingManager;
                this.connectionManager = connectionManager;
            }

            public void Start()
            {
                while (true)
                {
                    Tick();
                    Thread.Sleep(10.Milliseconds());
                }
            }

            private void Tick()
            {
                connectionManager.PurgeDeadConnections();
                var selectResult = connectionManager.Select();

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

                routingManager.UpdateConnections();

                routingManager.PullMaps(selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected));
                routingManager.PushMaps(selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected));

                //routingManager.DisconnectExcessLinks();
                routingManager.ConnectNewLinks();

                Console.WriteLine("[{0}] v: {2} {1}", routingManager.Map.OwnAddress, routingManager.Map, routingManager.Map.Version);
            }

            private readonly RoutingManager routingManager;
            private readonly TcpConnectionManager connectionManager;
        }
    }
}