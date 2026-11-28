using PCPorter.App.Infrastructure;

namespace PCPorter.App.Tests;

public class SingleInstanceTests
{
    [Fact]
    public void A_second_start_asks_the_first_to_come_forward_and_does_not_claim()
    {
        var name = "PCPorterTest-" + Guid.NewGuid().ToString("N");
        using var asked = new ManualResetEventSlim();
        using var first = SingleInstance.TryClaim(asked.Set, name);
        Assert.NotNull(first);

        var second = SingleInstance.TryClaim(() => Assert.Fail("the second start must not listen"), name);
        Assert.Null(second);
        Assert.True(asked.Wait(TimeSpan.FromSeconds(5)), "the first instance was not asked to come forward");
    }

    [Fact]
    public void After_the_first_exits_a_new_start_claims_again()
    {
        var name = "PCPorterTest-" + Guid.NewGuid().ToString("N");
        SingleInstance.TryClaim(() => { }, name)!.Dispose();
        using var again = SingleInstance.TryClaim(() => { }, name);
        Assert.NotNull(again);
    }
}
