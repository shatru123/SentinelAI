using Xunit;

namespace SentinelAI.UnitTests;

[CollectionDefinition("Browser acceptance", DisableParallelization = true)]
public sealed class BrowserAcceptanceCollection
{
    public const string Name = "Browser acceptance";
}
