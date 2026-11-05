using Microsoft.Playwright;

namespace SentinelAI.UnitTests;

internal static class BrowserScreenshotArtifacts
{
    public static async Task CaptureAsync(IPage page, string fileName)
    {
        var outputDirectory = Environment.GetEnvironmentVariable("SENTINELAI_SCREENSHOT_DIR");
        if (string.IsNullOrWhiteSpace(outputDirectory))
            return;

        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, fileName);
        await page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = path,
            FullPage = true,
            Animations = ScreenshotAnimations.Disabled
        });
    }
}
