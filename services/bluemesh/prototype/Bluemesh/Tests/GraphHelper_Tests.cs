using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Node.Connections;
using Node.Routing;
using Node.Serialization;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class GraphHelper_Tests
    {
        [Test]
        public void CalculateConnectivity_should_count_components()
        {
            var graph = Graph(Links(0, 1, 2, 0), Links(3, 4, 5, 3), Links(6, 7));

            Console.WriteLine(graph.ToDOT());

            GraphHelper.CalculateConnectivity(graph)
                .ConnectedComponents.Should().Be(3);
        }

        [Test]
        public void CalculateConnectivity_should_correctly_count_bicomponents_in_small_components()
        {
            var graph = Graph(Links(0, 1, 2, 0), Links(3, 4, 5, 3), Links(6, 7));

            Console.WriteLine(graph.ToDOT());

            var connectivity = GraphHelper.CalculateConnectivity(graph);
            connectivity.ConnectedComponents.Should().Be(3);
            connectivity.BiconnectedComponents.Should().Be(3);
        }

        [Test]
        public void CalculateConnectivity_should_correctly_count_bicomponents_in_big_components()
        {
            var graph = Graph(Links(0, 1, 2, 3, 4, 5, 3, 2, 0), Links(10, 11, 12, 13, 14, 15, 16, 13, 10));

            Console.WriteLine(graph.ToDOT());

            var connectivity = GraphHelper.CalculateConnectivity(graph);
            connectivity.ConnectedComponents.Should().Be(2);
            connectivity.BiconnectedComponents.Should().Be(5);
        }
        
        [Test]
        public void CalculateConnectivity_should_correctly_count_bicomponents_in_one_component()
        {
            var graph = Graph(Links(0, 1, 2, 3, 4, 5, 6, 3, 7, 8, 9, 10, 7, 11, 12, 13, 14, 11, 2, 15, 0));

            Console.WriteLine(graph.ToDOT());

            var connectivity = GraphHelper.CalculateConnectivity(graph);
            connectivity.ConnectedComponents.Should().Be(1);
            connectivity.BiconnectedComponents.Should().Be(5);
        }
        
        [Test]
        public void CalculateConnectivity_should_correctly_count_bicomponents_in_line()
        {
            var graph = Graph(Links(0, 1, 2, 3, 4));

            Console.WriteLine(graph.ToDOT());

            var connectivity = GraphHelper.CalculateConnectivity(graph);
            connectivity.ConnectedComponents.Should().Be(1);
            connectivity.BiconnectedComponents.Should().Be(4);
        }
        
        [Test]
        public void CalculateConnectivity_should_correctly_count_bicomponents_in_circle()
        {
            var graph = Graph(Links(0, 1, 2, 3, 4, 0));

            Console.WriteLine(graph.ToDOT());

            var connectivity = GraphHelper.CalculateConnectivity(graph);
            connectivity.ConnectedComponents.Should().Be(1);
            connectivity.BiconnectedComponents.Should().Be(1);
        }

        private static List<RoutingMapLink> Graph(params IEnumerable<RoutingMapLink>[] links)
        {
            return links.SelectMany(_ => _).Distinct().ToList();
        }

        private static IEnumerable<RoutingMapLink> Links(params FakeAddress[] nodes)
        {
            for (int i = 1; i < nodes.Length; i++)
                yield return new RoutingMapLink(nodes[i - 1], nodes[i]);
        }

        private struct FakeAddress : IAddress
        {
            private FakeAddress(int value)
            {
                this.value = value;
            }

            public void Serialize(IBinarySerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override string ToString()
            {
                return value.ToString();
            }

            public static implicit operator FakeAddress(int value)
            {
                return new FakeAddress(value);
            }

            public static implicit operator int(FakeAddress address)
            {
                return address.value;
            }

            private readonly int value;
        }
    }
}
