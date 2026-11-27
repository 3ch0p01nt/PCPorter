using PCPorter.Core.Time;

namespace PCPorter.Core.Tests.Time;

public class TimestampsTests
{
    static readonly DateTimeOffset Y2K = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact] public void WebKit_converts() =>   // Chromium: microseconds since 1601-01-01
        Assert.Equal(Y2K, Timestamps.FromWebKit(12_591_158_400_000_000L));

    [Fact] public void PRTime_converts() =>   // Firefox: microseconds since 1970-01-01
        Assert.Equal(Y2K, Timestamps.FromPRTime(946_684_800_000_000L));

    [Fact] public void FileTime_converts() => // Windows: 100ns ticks since 1601-01-01
        Assert.Equal(Y2K, Timestamps.FromFileTime(125_911_584_000_000_000L));

    [Theory, InlineData(0L), InlineData(-1L)]
    public void Zero_or_negative_is_null(long v)
    {
        Assert.Null(Timestamps.FromWebKit(v));
        Assert.Null(Timestamps.FromPRTime(v));
        Assert.Null(Timestamps.FromFileTime(v));
    }

    [Fact] public void Absurd_values_are_null() =>  // corrupt data must not throw
        Assert.Null(Timestamps.FromWebKit(long.MaxValue));
}
