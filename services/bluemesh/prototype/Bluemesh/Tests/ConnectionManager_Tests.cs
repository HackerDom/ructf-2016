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
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class ConnectionManager_Tests
    {
        [Explicit, Timeout(20000)]
        [TestCase(0)]
        [TestCase(0.5)]
        public void Measure_fully_interconnected_communication(double errorProbability)
        {
            var nodes = Enumerable.Range(0, 2).Select(i => new TestNode(new LocalTcpConnectionManager(), errorProbability)).ToList();

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

        private class TestNode
        {
            public TestNode(LocalTcpConnectionManager connectionManager, double errorProbability = 0)
            {
                this.connectionManager = connectionManager;
                this.errorProbability = errorProbability;
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
                var stopped = false;
                var nukerTask = null as Task;
                if (errorProbability > 0)
                {
                    nukerTask = Task.Run(async () =>
                    {
                        var r = new Random();
                        while (!stopped)
                        {
                            await Task.Delay(100);
                            var connections = connectionManager.Connections;
                            if (connections.Count > 0 && r.NextDouble() < errorProbability)
                            {
                                ((LocalTcpConnection) connections[r.Next(connections.Count)]).Socket.Close();
                                Console.WriteLine("Nuked some connections, hehe");
                                break;
                            }
                        }
                    });
                }
                int ticks = 0;
                while (stages.Count < peerCount || stages.Values.Any(s => !s.Completed))
                {
                    Tick();
                    ticks++;

                    Console.WriteLine("[{0}] Tick result: {1} connections, {2} completed", 
                        connectionManager.Address, connectionManager.Connections.Count, stages.Values.Count(s => s.Completed));
                }
                stopped = true;
                nukerTask?.Wait();
                Console.WriteLine("[{0}] {1} ticks elapsed", connectionManager.Address, ticks);
            }

            private void Tick()
            {
                var countBefore = connectionManager.Connections.Count;
                connectionManager.PurgeDeadConnections();
                var countAfter = connectionManager.Connections.Count;
                if (countBefore > countAfter)
                    Console.WriteLine("Purged {0} connections", countBefore - countAfter);
                try
                {
                    foreach (var peer in connectionManager.GetAvailablePeers())
                        connectionManager.Connect(peer);
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
                foreach (var connection in connectionManager.Connections)
                {
                    CommunicationStrategy stage;
                    if (!stages.TryGetValue(connection.RemoteAddress, out stage))
                        stages[connection.RemoteAddress] = strategyBuilder.Build();
                }
                foreach (var connection in selectResult.ReadableConnections)
                {
                    stages[connection.RemoteAddress].Step(connection, true, false);
                }
                foreach (var connection in selectResult.WritableConnections)
                {
                    stages[connection.RemoteAddress].Step(connection, false, true);
                }
            }

            private readonly Dictionary<IAddress, CommunicationStrategy> stages = new Dictionary<IAddress, CommunicationStrategy>();
            private readonly LocalTcpConnectionManager connectionManager;
            private readonly double errorProbability;
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
            return writable && connection.Send(message) == SendResult.Success;
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