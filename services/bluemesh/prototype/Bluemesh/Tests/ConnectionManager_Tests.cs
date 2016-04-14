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
using Node.Encryption;
using Node.Messages;
using Node.Routing;
using NSubstitute;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class ConnectionManager_Tests
    {
        [Test, Explicit, Timeout(20000)]
        public void Measure_fully_interconnected_communication()
        {
            var routingConfig = Substitute.For<IRoutingConfig>();
            routingConfig.MaxConnections.Returns(int.MaxValue);
            var preconfiguredNodes = new List<IAddress>();
            var nodes = Enumerable.Range(0, 10).Select(i => CreateNode(routingConfig, preconfiguredNodes, i)).ToList();

            ThreadPool.SetMinThreads(nodes.Count * 2, nodes.Count * 2);

            var trigger = new ManualResetEventSlim();
            var tasks = nodes.Select(n => Task.Run(() =>
            {
                trigger.Wait();
                n.Start(nodes.Count - 1);
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
            var encryptionManager = Substitute.For<IEncryptionManager>();
            var encoder = Substitute.For<IMessageEncoder>();
            encryptionManager.CreateEncoder(Arg.Any<IAddress>()).Returns(encoder);
            return new TestNode(new TcpConnectionManager(connectionConfig, routingConfig, encryptionManager));
        }

        private class TestNode
        {
            public TestNode(TcpConnectionManager connectionManager)
            {
                this.connectionManager = connectionManager;
                var id = connectionManager.Address;
                strategyBuilder = CommunicationStrategyBuilder.Start()
                    .Send(new StringMessage("hello from " + id))
                    .Receive(conn => new StringMessage("hello from " + conn.RemoteAddress))
                    .Wait(100.Milliseconds())
                    .Send(new StringMessage("ping from " + id))
                    .Receive(conn => new StringMessage("ping from " + conn.RemoteAddress))
                    .Wait(100.Milliseconds())
                    .Send(new StringMessage("ping from " + id))
                    .Receive(conn => new StringMessage("ping from " + conn.RemoteAddress))
                    .Wait(100.Milliseconds())
                    .Send(new StringMessage("ping from " + id))
                    .Receive(conn => new StringMessage("ping from " + conn.RemoteAddress))
                    .Wait(100.Milliseconds())
                    .Send(new StringMessage("bye from " + id))
                    .Receive(conn => new StringMessage("bye from " + conn.RemoteAddress));
            }

            public void Start(int peerCount)
            {
                int ticks = 0;
                while (stages.GroupBy(pair => pair.Key.RemoteAddress).Count(g => g.Any(pair => pair.Value.Completed)) < peerCount)
                {
                    Tick();
                    ticks++;

                    Console.WriteLine("[{0}] Tick result: {1} connections, {2} completed", 
                        connectionManager.Address, connectionManager.EstablishedConnections.Count(), stages.Values.Count(s => s.Completed));
                    Console.WriteLine("[{0}] Progress: {1}", connectionManager.Address, string.Join(", ", stages.Values.Select(s => s.Progress.ToString("f2"))));
                }
                Console.WriteLine("[{0}] {1} ticks elapsed", connectionManager.Address, ticks);
            }

            private void Tick()
            {
                var countBefore = connectionManager.Connections.Count;
                connectionManager.PurgeDeadConnections();
                var countAfter = connectionManager.Connections.Count;
                //if (countBefore > countAfter)
                //    Console.WriteLine("Purged {0} connections", countBefore - countAfter);
                try
                {
                    foreach (var peer in connectionManager.GetAvailablePeers())
                        connectionManager.TryConnect(peer);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                var selectResult = connectionManager.Select();
                if (selectResult == null)
                    return;
                //Console.WriteLine("[{0}] Select result: {1} readable, {2} writable",
                //    connectionManager.Address, selectResult.ReadableConnections.Count, selectResult.WritableConnections.Count);
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
                foreach (var connection in connectionManager.EstablishedConnections)
                {
                    CommunicationStrategy stage;
                    if (!stages.TryGetValue(connection, out stage))
                        stages[connection] = strategyBuilder.Build();
                }
                foreach (var connection in selectResult.ReadableConnections.Where(c => c.State == ConnectionState.Connected))
                {
                    //Console.WriteLine("readable step");
                    stages[connection].Step(connection, true, false);
                }
                foreach (var connection in selectResult.WritableConnections.Where(c => c.State == ConnectionState.Connected))
                {
                    //Console.WriteLine("writable step");
                    stages[connection].Step(connection, false, true);
                }
            }

            private readonly Dictionary<IConnection, CommunicationStrategy> stages = new Dictionary<IConnection, CommunicationStrategy>();
            private readonly TcpConnectionManager connectionManager;
            private readonly CommunicationStrategyBuilder strategyBuilder;
        }
    }

    internal class CommunicationStrategyBuilder
    {
        public static CommunicationStrategyBuilder Start()
        {
            return new CommunicationStrategyBuilder();
        }

        public CommunicationStrategyBuilder Send(IMessage message)
        {
            steps.Add(new SendStep(message));
            return this;
        }

        public CommunicationStrategyBuilder Receive(Func<IConnection, IMessage> messageForConnection)
        {
            steps.Add(new ReceiveStep(messageForConnection));
            return this;
        }

        public CommunicationStrategyBuilder Wait(TimeSpan delay)
        {
            steps.Add(new WaitStep(delay));
            return this;
        }

        public CommunicationStrategy Build()
        {
            return new CommunicationStrategy(steps);
        }

        private readonly List<ICommunicationStep> steps = new List<ICommunicationStep>();
    }

    internal class CommunicationStrategy
    {
        public CommunicationStrategy(List<ICommunicationStep> steps)
        {
            this.steps = steps;
        }

        public void Step(IConnection connection, bool readable, bool writable)
        {
            if (Completed)
                return;
              
            if (steps[currentStep].Execute(connection, readable, writable))
                currentStep++;
        }

        public bool Completed => currentStep >= steps.Count;
        public double Progress => (double) currentStep / steps.Count;

        private int currentStep;
        private readonly List<ICommunicationStep> steps;
    }

    internal interface ICommunicationStep
    {
        bool Execute(IConnection connection, bool readable, bool writable);
    }

    internal class SendStep : ICommunicationStep
    {
        public SendStep(IMessage message)
        {
            this.message = message;
        }

        public bool Execute(IConnection connection, bool readable, bool writable)
        {
            //return writable && connection.Send(message) == SendResult.Success;
            if (writable)
            {
                var result = connection.Send(message);
                //Console.WriteLine("Send {0} by {1} <-> {2} ({3}) : {4}", message, connection.LocalAddress, connection.RemoteAddress, connection.GetHashCode(), result);
                return result == SendResult.Success;
            }
            return false;
        }

        private readonly IMessage message;
    }

    internal class ReceiveStep : ICommunicationStep
    {
        public ReceiveStep(Func<IConnection, IMessage> messageForConnection)
        {
            this.messageForConnection = messageForConnection;
        }

        public bool Execute(IConnection connection, bool readable, bool writable)
        {
            if (!readable)
                return false;
            var result = connection.Receive();
            //Console.WriteLine("Receive by {0} <-> {1} ({2}) : {3}", connection.LocalAddress, connection.RemoteAddress, connection.GetHashCode(), result);
            if (result == null)
                return false;
            result.Should().Be(messageForConnection(connection));
            return true;
        }

        private readonly Func<IConnection, IMessage> messageForConnection;
    }

    internal class WaitStep : ICommunicationStep
    {
        public WaitStep(TimeSpan delay)
        {
            this.delay = delay;
        }

        public bool Execute(IConnection connection, bool readable, bool writable)
        {
            if (watch == null)
                watch = Stopwatch.StartNew();
            return watch.Elapsed >= delay;
        }

        private Stopwatch watch;
        private readonly TimeSpan delay;
    }
}