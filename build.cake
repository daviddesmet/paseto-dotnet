#tool nuget:?package=ReportGenerator&version=5.3.0

var target = Argument("Target", "Default");
var configuration =
    HasArgument("Configuration") ? Argument<string>("Configuration") :
    EnvironmentVariable("Configuration", "Release");

var artifactsDirectory = Directory("./Artifacts");

Task("Clean")
    .Description("Cleans the artifacts, bin and obj directories.")
    .Does(() =>
    {
        CleanDirectory(artifactsDirectory);
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
                //ArgumentCustomization = args => args.Append($"--diag:{artifactsDirectory}/log.txt"),
                Blame = true,
                Collectors = new string[] { "XPlat Code Coverage" },
                Configuration = configuration,
                Framework = "net6.0",
                Loggers = new string[]
                {
                    $"trx;LogFileName={project.GetFilenameWithoutExtension()}.trx",
                    $"html;LogFileName={project.GetFilenameWithoutExtension()}.html",
                },
                NoBuild = true,
                NoRestore = true,
                ResultsDirectory = $"{artifactsDirectory}/TestResults",
                Settings = "CodeCoverage.runsettings"
            });
    });

Task("CoverageReport")
    .IsDependentOn("Test")
    .Does(() =>
    {
        ReportGenerator(report: $"{artifactsDirectory}/TestResults/**/coverage.cobertura.xml",
                        targetDir: new DirectoryPath($"{artifactsDirectory}/TestResults/Coverage/Reports"),
                        settings: new ReportGeneratorSettings
                        {
                            ArgumentCustomization = args => args.Append("-reporttypes:HtmlInline;HTMLChart;Cobertura")
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
                OutputDirectory = artifactsDirectory,
            });
    });

Task("Default")
    .Description("Cleans, restores NuGet packages, builds the solution, runs unit tests and then create the NuGet packages.")
    .IsDependentOn("Build")
    .IsDependentOn("Test")
    .IsDependentOn("CoverageReport")
    .IsDependentOn("Pack");

RunTarget(target);
