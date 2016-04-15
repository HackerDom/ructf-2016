using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FluentAssertions;
using Node.Connections;
using Node.Routing;
using Node.Serialization;
using NSubstitute;
using NUnit.Framework;

namespace Tests
{
    [TestFixture]
    internal class RoutingMap_Tests
    {
        [Test]
        public void Merge_should_correctly_comapre_maps_from_real_case()
        {
            var g1 = ParseDOT(@"
graph  {
        172161610116800 -- 172161610416800; // v: 1
        172161610116800 -- 172161610316800; // v: 1
        172161611316800 -- 172161610416800; // v: 1
        172161611416800 -- 172161610716800; // v: 1
        172161611416800 -- 172161611116800; // v: 1
        172161611516800 -- 172161610516800; // v: 1
        172161611516800 -- 172161611016800; // v: 1
        172161611516800 -- 172161610216800; // v: 1
        172161611416800 -- 172161611516800; // v: 1
        172161611516800 -- 172161611616800; // v: 1
        172161611516800 -- 172161611216800; // v: 1
        172161611616800 -- 172161611216800; // v: 1
        172161611516800 -- 172161610316800; // v: 1
        172161611616800 -- 172161611016800; // v: 1
        172161611516800 -- 172161611116800; // v: 1
        172161611716800 -- 172161610916800; // v: 1
        172161610116800 -- 172161611816800; // v: 1
        172161611716800 -- 172161610716800; // v: 1
        172161611916800 -- 172161610716800; // v: 1
        172161611916800 -- 172161610316800; // v: 1
        172161612016800 -- 172161611216800; // v: 1
        172161612016800 -- 172161610516800; // v: 1
        172161612016800 -- 172161611116800; // v: 1
        172161612116800 -- 172161611016800; // v: 1
        172161612116800 -- 172161610916800; // v: 1
        172161611916800 -- 172161610416800; // v: 1
        172161612116800 -- 172161610516800; // v: 1
        172161612016800 -- 172161610616800; // v: 1
        172161612116800 -- 172161610616800; // v: 1
        172161610816800 -- 172161610216800; // v: 1
        172161610816800 -- 172161611716800; // v: 1
        172161610816800 -- 172161611516800; // v: 1
        172161610216800 -- 172161611816800; // v: 3
        172161610916800 -- 172161611316800; // v: 3
        172161611316800 -- 172161611816800; // v: 3
        172161611316800 -- 172161610616800; // v: 3
}
");
            var g2 = ParseDOT(@"
graph  {
        172161610216800 -- 172161610816800; // v: 1
        172161610116800 -- 172161610416800; // v: 1
        172161610116800 -- 172161610316800; // v: 1
        172161611316800 -- 172161610416800; // v: 1
        172161610716800 -- 172161611416800; // v: 1
        172161611116800 -- 172161611416800; // v: 1
        172161611216800 -- 172161611616800; // v: 1
        172161611616800 -- 172161611016800; // v: 1
        172161610916800 -- 172161611716800; // v: 1
        172161611716800 -- 172161610816800; // v: 1
        172161610116800 -- 172161611816800; // v: 1
        172161611716800 -- 172161610716800; // v: 1
        172161611916800 -- 172161610716800; // v: 1
        172161611916800 -- 172161610316800; // v: 1
        172161612016800 -- 172161611216800; // v: 1
        172161612016800 -- 172161610516800; // v: 1
        172161612016800 -- 172161611116800; // v: 1
        172161611916800 -- 172161610416800; // v: 1
        172161611016800 -- 172161612116800; // v: 1
        172161612116800 -- 172161610516800; // v: 1
        172161612116800 -- 172161610916800; // v: 1
        172161612016800 -- 172161610616800; // v: 1
        172161612116800 -- 172161610616800; // v: 1
        172161610216800 -- 172161611816800; // v: 3
        172161610616800 -- 172161611316800; // v: 3
        172161610916800 -- 172161611316800; // v: 3
        172161611316800 -- 172161611816800; // v: 3
        172161611516800 -- 172161610216800; // v: 1
        172161611516800 -- 172161611416800; // v: 1
        172161611516800 -- 172161611616800; // v: 1
        172161611516800 -- 172161611216800; // v: 1
        172161611516800 -- 172161610316800; // v: 1
        172161611516800 -- 172161611116800; // v: 1
        172161611516800 -- 172161610516800; // v: 1
        172161611516800 -- 172161611016800; // v: 1
        172161611516800 -- 172161610816800; // v: 1
}
");

            var config = Substitute.For<IRoutingConfig>();
            config.DesiredConnections.Returns(3);

            g1.AreEquivalent(g2).Should().BeTrue();
            var map1 = new RoutingMap(new FakeAddress("172161610816800"), g1, config);
            map1.IsLinkExcess(new RoutingMapLink(new FakeAddress("172161611516800"), new FakeAddress("172161610816800")))
                .Should().BeTrue();
            var map2 = new RoutingMap(new FakeAddress("172161611516800"), g2, config);
            map2.IsLinkExcess(new RoutingMapLink(new FakeAddress("172161611516800"), new FakeAddress("172161610816800")))
                .Should().BeTrue();
        }
        
        private static List<RoutingMapLink> ParseDOT(string dot)
        {
            var match = Regex.Match(dot, @"\{\s*(?:\s*(?<left>\w+)\s*--\s*(?<right>\w+)\s*;\s*(?://.*?v:\s*(?<v>\d+).*?\n))*\s*\}", RegexOptions.Singleline);
            return match.Groups["left"].Captures.Cast<Capture>()
                .Zip(match.Groups["right"].Captures.Cast<Capture>(),
                    (c1, c2) => new RoutingMapLink(new FakeAddress(c1.Value), new FakeAddress(c2.Value)))
                .Zip(match.Groups["v"].Captures.Cast<Capture>(), 
                    (link, v) => new RoutingMapLink(link.A, link.B, int.Parse(v.Value), true)).ToList();
        }

        private class FakeAddress : IAddress
        {
            public FakeAddress(string name)
            {
                Name = name;
            }

            public void Serialize(IBinarySerializer serializer)
            {
                throw new NotImplementedException();
            }

            public readonly string Name;

            public override string ToString()
            {
                return Name;
            }

            private bool Equals(FakeAddress other)
            {
                return string.Equals(Name, other.Name);
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((FakeAddress) obj);
            }

            public override int GetHashCode()
            {
                return Name.GetHashCode();
            }
        }
    }
}