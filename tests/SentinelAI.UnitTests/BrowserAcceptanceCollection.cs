using Xunit;

namespace SentinelAI.UnitTests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class BrowserAcceptanceCollection
{
    public const string Name = "Browser acceptance";
}
