using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Node.Connections;
using Node.Connections.LocalTcp;
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
            config.DesiredConnections.Returns(3);
            config.MaxConnections.Returns(3);
            var nodes = Enumerable.Range(0, 5).Select(i => MakeNode(config)).ToList();

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

        private static TestNode MakeNode(IRoutingConfig config)
        {
            var connectionManager = new LocalTcpConnectionManager(config);
            return new TestNode(new RoutingManager(connectionManager, config), connectionManager);
        }

        private class TestNode
        {
            public TestNode(RoutingManager routingManager, LocalTcpConnectionManager connectionManager)
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
            private readonly LocalTcpConnectionManager connectionManager;
        }
    }
}