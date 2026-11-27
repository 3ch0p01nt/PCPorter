using PCPorter.Collectors.Security;

namespace PCPorter.Collectors.Tests.Security;

public class ProductStateTests
{
    [Theory]
    [InlineData(266240u, WscState.On, true, false)]      // third-party, on, up to date
    [InlineData(397568u, WscState.On, true, true)]       // Defender on this PC
    [InlineData(397584u, WscState.On, false, true)]      // on, out of date
    [InlineData(262160u, WscState.Off, false, false)]    // off, out of date
    [InlineData(393472u, WscState.Off, true, true)]      // off
    [InlineData(0x52000u, WscState.Snoozed, true, false)]
    [InlineData(0x53000u, WscState.Expired, true, false)]
    public void Decodes(uint raw, WscState state, bool upToDate, bool microsoft) =>
        Assert.Equal(new ProductStatus(state, upToDate, microsoft), ProductState.Decode(raw));

    [Fact]
    public void Unknown_state_nibble() => Assert.Equal(WscState.Unknown, ProductState.Decode(0x5F000).State);

    [Fact]
    public void Describes_expired_as_license_expired() => Assert.Equal("license expired", ProductState.Describe(ProductState.Decode(0x53000)));
}
