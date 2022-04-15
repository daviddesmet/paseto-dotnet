var target = Argument("Target", "Default");
var configuration =
    HasArgument("Configuration") ? Argument<string>("Configuration") :
    EnvironmentVariable("Configuration", "Release");

var artefactsDirectory = Directory("./Artifacts");

Task("Clean")
    .Description("Cleans the artifacts, bin and obj directories.")
    .Does(() =>
    {
        CleanDirectory(artefactsDirectory);
        DeleteDirectories(GetDirectories("**/bin"), new DeleteDirectorySettings() { Force = true, Recursive = true });
        DeleteDirectories(GetDirectories("**/obj"), new DeleteDirectorySettings() { Force = true, Recursive = true });
    });

Task("Restore")
    .Description("Restores NuGet packages.")
    .IsDependentOn("Clean")
    .Does(() =>
    {
        DotNetRestore();
    });

Task("Build")
    .Description("Builds the solution.")
    .IsDependentOn("Restore")
    .Does(() =>
    {
        DotNetBuild(
            ".",
            new DotNetBuildSettings()
            {
                Configuration = configuration,
                NoRestore = true,
            });
    });

Task("Test")
    .Description("Runs unit tests and outputs test results to the artifacts directory.")
    .DoesForEach(GetFiles("./tests/**/*.Tests.csproj"), project =>
    {
        Information($"Preparing {project.GetFilename()} for test");

        DotNetTest(
            project.ToString(),
            new DotNetTestSettings()
            {
                Blame = true,
                Collectors = new string[] { "Code Coverage", "XPlat Code Coverage" },
                Configuration = configuration,
                Framework = "net6.0",
                Loggers = new string[]
                {
                    $"trx;LogFileName={project.GetFilenameWithoutExtension()}.trx",
                    $"html;LogFileName={project.GetFilenameWithoutExtension()}.html",
                },
                NoBuild = true,
                NoRestore = true,
                ResultsDirectory = artefactsDirectory,
            });
    });

Task("Pack")
    .Description("Creates the NuGet packages and outputs them to the artifacts directory.")
    .Does(() =>
    {
        DotNetPack(
            "./src/Paseto/",
            new DotNetPackSettings()
            {
                Configuration = configuration,
                IncludeSymbols = false,
                MSBuildSettings = new DotNetMSBuildSettings()
                {
                    ContinuousIntegrationBuild = !BuildSystem.IsLocalBuild,
                },
                NoBuild = true,
                NoRestore = true,
                OutputDirectory = artefactsDirectory,
            });
    });

Task("Default")
    .Description("Cleans, restores NuGet packages, builds the solution, runs unit tests and then create the NuGet packages.")
    .IsDependentOn("Build")
    .IsDependentOn("Test")
    .IsDependentOn("Pack");

RunTarget(target);
