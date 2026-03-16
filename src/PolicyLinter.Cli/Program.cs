namespace Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Cli
{
    using System;
    using System.Collections.Generic;
    using System.CommandLine;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Threading.Tasks;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Metadata;
    using Microsoft.WindowsAzure.Governance.Policy.PolicyLinter.Parsing;
    using Newtonsoft.Json;

    /// <summary>
    /// The linter program entry point.
    /// </summary>
    public class Program
    {
        private const int MaxFileLimit = 1000;
        private const string DefaultRuleSetName = "default";

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        /// <param name="args">args.</param>
        public static async Task<int> Main(string[] args)
        {
            var filesArgument = new Argument<string[]>(
                name: "files",
                description: "Zero or more policy definition files to lint. If omitted, use --list-rule-sets to list available rule sets.");
            filesArgument.Arity = ArgumentArity.ZeroOrMore;

#pragma warning disable CA1861 // Avoid constant arrays as arguments
            var outputOption = new Option<FileInfo?>(
                aliases: new string[] { "--output", "-o" },
                description: "Output file path for JSON results. If not specified, results are written to console.");
            outputOption.IsRequired = false;

            var listRuleSetsOption = new Option<bool>(
                aliases: new string[] { "--list-rule-sets" },
                description: "List all available rule sets and exit.");
            listRuleSetsOption.IsRequired = false;

            var ruleSetsOption = new Option<string[]?>(
                aliases: new string[] { "--rule-set", "-r" },
                description: "One or more rule set names to apply. If not specified, the default rule set is applied. Use --list-rule-sets to see available sets.");
            ruleSetsOption.IsRequired = false;
#pragma warning restore CA1861 // Avoid constant arrays as arguments

            var rootCommand = new RootCommand("A linter for Azure Policy definitions that identifies issues and provides best practice recommendations.");
            rootCommand.AddArgument(filesArgument);
            rootCommand.AddOption(outputOption);
            rootCommand.AddOption(listRuleSetsOption);
            rootCommand.AddOption(ruleSetsOption);

            rootCommand.SetHandler(async (string[] files, FileInfo? outputFile, bool listRuleSets, string[]? ruleSets) =>
            {
                if (listRuleSets)
                {
                    Program.ListRuleSets();
                    return;
                }

                if (files == null || files.Length == 0)
                {
                    Program.Error("At least one policy definition file must be specified.");
                    Environment.Exit(1);
                }

                await Program.RunLinter(
                    filePaths: files,
                    outputFile: outputFile?.FullName,
                    ruleSets: ruleSets).ConfigureAwait(false);
            }, filesArgument, outputOption, listRuleSetsOption, ruleSetsOption);

            return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        }

        /// <summary>
        /// Runs the linter with the specified parameters.
        /// </summary>
        /// <param name="filePaths">The file paths to lint.</param>
        /// <param name="outputFile">The optional output file path.</param>
        /// <param name="ruleSets">The optional rule set names to filter by.</param>
        private static async Task RunLinter(string[] filePaths, string? outputFile, string[]? ruleSets)
        {
            if (filePaths.Length > MaxFileLimit)
            {
                Program.Error($"Too many files specified ({filePaths.Length}). Maximum allowed: {MaxFileLimit}");
                Environment.Exit(1);
            }

            var absoluteToInputPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var filePath in filePaths)
            {
                var absolutePath = Path.GetFullPath(filePath);

                if (!absoluteToInputPaths.TryAdd(absolutePath, filePath))
                {
                    Program.Warning($"Duplicate file path detected and skipped: {filePath}");
                }
            }


            var metadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

            var allRules = Program.GetAllAvailableRules();
            var rules = Program.FilterRulesByRuleSets(allRules: allRules, ruleSets: ruleSets);

            Program.PrintRuleSetInfo(ruleSets: ruleSets);

            var linter = new PolicyLinter(rules: rules, metadata: metadata);

            var uniqueFilePaths = absoluteToInputPaths.Keys.ToArray();
            var allResults = await Program.ProcessFiles(filePaths: uniqueFilePaths, linter: linter).ConfigureAwait(false);

            // Results are keyed by the original input paths provided by the caller,
            // not the internally resolved absolute paths used for file I/O and deduplication.
            var outputResults = allResults.ToDictionary(
                kvp => absoluteToInputPaths[kvp.Key],
                kvp => kvp.Value);

            if (outputFile != null)
            {
                var json = JsonConvert.SerializeObject(outputResults, LinterOutputSerializerSettings.Settings);
                await File.WriteAllTextAsync(outputFile, json).ConfigureAwait(false);
                Program.Success($"Results written to {outputFile}");
            }
            else
            {
                foreach (var (filePath, results) in outputResults)
                {
                    if (outputResults.Count > 1)
                    {
                        Program.DisplayFileResultsHeading($"Results for: {filePath}");
                        Console.WriteLine();
                    }
                    Program.DisplayResults(results: results);
                }
            }

            Program.Success("Done!");
        }

        /// <summary>
        /// Lists all available rule sets grouped by name.
        /// </summary>
        private static void ListRuleSets()
        {
            var ruleSetsInfo = Program.GetRuleSetsInfo();

            Program.Info("Available rule sets:");
            Console.WriteLine();

            foreach (var (ruleSetName, ruleCount) in ruleSetsInfo.OrderBy(kvp => kvp.Key))
            {
                Program.Info($"  {ruleSetName}: {ruleCount} rule(s)");
            }
        }

        /// <summary>
        /// Prints information about the rule sets being used for linting.
        /// </summary>
        /// <param name="ruleSets">The rule sets specified by the user, or null/empty for default.</param>
        private static void PrintRuleSetInfo(string[]? ruleSets)
        {
            var allRuleSetsInfo = Program.GetRuleSetsInfo();
            var usingDefaultSet = ruleSets == null || ruleSets.Length == 0;

            if (usingDefaultSet)
            {
                Program.Info($"Linting using '{Program.DefaultRuleSetName}' rule set.");

                var otherRuleSets = allRuleSetsInfo
                    .Where(kvp => !string.Equals(kvp.Key, Program.DefaultRuleSetName, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(kvp => kvp.Key)
                    .ToArray();

                if (otherRuleSets.Length != 0)
                {
                    var ruleSetNames = string.Join(", ", otherRuleSets.Select(kvp => $"'{kvp.Key}'"));
                    Program.DarkGray($"Additional rule sets are available: {ruleSetNames}. Use --rule-set to specify them explicitly.");
                }
            }
            else
            {
                var ruleSetNames = string.Join(", ", ruleSets!.Select(name => $"'{name}'"));
                Program.Info($"Linting using rule sets: {ruleSetNames}.");
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Gets information about all available rule sets.
        /// </summary>
        /// <returns>A dictionary mapping rule set names to the count of rules in each set.</returns>
        private static Dictionary<string, int> GetRuleSetsInfo()
        {
            var ruleTypes = Program.GetAllRuleTypes();
            var ruleSets = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var ruleType in ruleTypes)
            {
                var ruleSetAttribute = ruleType.GetCustomAttribute<RuleSetAttribute>();
                var ruleSetName = ruleSetAttribute?.Name ?? Program.DefaultRuleSetName;

                if (!ruleSets.TryGetValue(ruleSetName, out int value))
                {
                    value = 0;
                    ruleSets[ruleSetName] = value;
                }

                ruleSets[ruleSetName] = ++value;
            }

            return ruleSets;
        }

        /// <summary>
        /// Gets all rule types that implement <see cref="ILinterRule"/>.
        /// </summary>
        /// <returns>An array of rule types.</returns>
        private static Type[] GetAllRuleTypes()
        {
            var coreAssembly = typeof(ILinterRule).Assembly;

            var ruleTypes = coreAssembly
                .GetTypes()
                .Where(type => !type.IsAbstract && !type.IsInterface && typeof(ILinterRule).IsAssignableFrom(type))
                .ToArray();

            return ruleTypes;
        }

        /// <summary>
        /// Gets all available linter rules.
        /// </summary>
        /// <returns>An array of all available linter rules.</returns>
        private static ILinterRule[] GetAllAvailableRules()
        {
            var ruleTypes = Program.GetAllRuleTypes();

            var rules = ruleTypes
                .Select(type =>
                {
                    var instance = Activator.CreateInstance(type);
                    if (instance == null)
                    {
                        throw new InvalidOperationException($"Failed to create instance of rule type: {type.FullName}");
                    }
                    return (ILinterRule)instance;
                })
                .ToArray();

            return rules;
        }

        /// <summary>
        /// Filters rules based on the specified rule sets.
        /// </summary>
        /// <remarks>
        /// Rule sets allow running different sets of linter rules depending on the scenario.
        /// For example, 1P change safety policies might require specific rules that wouldn't
        /// make sense in other contexts.
        /// </remarks>
        /// <param name="allRules">All available rules.</param>
        /// <param name="ruleSets">The rule set names to filter by. If null or empty, defaults to the "default" rule set.</param>
        /// <returns>An array of filtered rules.</returns>
        private static ILinterRule[] FilterRulesByRuleSets(ILinterRule[] allRules, string[]? ruleSets)
        {
            if (ruleSets == null || ruleSets.Length == 0)
            {
                ruleSets = new[] { Program.DefaultRuleSetName };
            }

            var ruleSetNames = new HashSet<string>(ruleSets, StringComparer.OrdinalIgnoreCase);
            var filteredRules = new List<ILinterRule>();

            foreach (var rule in allRules)
            {
                var ruleType = rule.GetType();
                var ruleSetAttribute = ruleType.GetCustomAttribute<RuleSetAttribute>();
                var ruleSetName = ruleSetAttribute?.Name ?? Program.DefaultRuleSetName;

                if (ruleSetNames.Contains(ruleSetName))
                {
                    filteredRules.Add(rule);
                }
            }

            return filteredRules.ToArray();
        }

        /// <summary>
        /// Processes files in parallel using Task.WhenAll.
        /// </summary>
        /// <param name="filePaths">The file paths to process.</param>
        /// <param name="linter">The linter instance.</param>
        /// <returns>A dictionary mapping file paths to linter outputs.</returns>
        private static async Task<Dictionary<string, LinterOutput[]>> ProcessFiles(
            string[] filePaths,
            PolicyLinter linter)
        {
            var tasks = filePaths.Select(async filePath =>
            {
                try
                {
                    var fileContent = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);

                    if (string.IsNullOrEmpty(fileContent))
                    {
                        var parsingError = BuiltinLinterOutputs.PolicyDefinitionParsingFailure("Empty file");
                        return new KeyValuePair<string, LinterOutput[]>(filePath, new[] { parsingError });
                    }

                    var results = linter.Lint(rawPolicyDefinition: fileContent, filePath: filePath);
                    return new KeyValuePair<string, LinterOutput[]>(filePath, results);
                }
                catch (FileNotFoundException)
                {
                    var errorResult = BuiltinLinterOutputs.FileNotFound(filePath);
                    return new KeyValuePair<string, LinterOutput[]>(filePath, new[] { errorResult });
                }
                catch (Exception ex)
                {
                    var errorResult = BuiltinLinterOutputs.FileReadError(filePath, ex.Message);
                    return new KeyValuePair<string, LinterOutput[]>(filePath, new[] { errorResult });
                }
            });

            var results = await Task.WhenAll(tasks).ConfigureAwait(false);
            return results.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        /// <summary>
        /// Displays the linting results for a file to the console.
        /// </summary>
        /// <param name="results">The linter results.</param>
        private static void DisplayResults(LinterOutput[] results)
        {
            foreach (var result in results)
            {
                switch (result.Severity)
                {
                    case Severity.Critical:
                    case Severity.Error:
                        Program.Error($"{result.Title}");
                        break;
                    case Severity.Warning:
                        Program.Warning($"{result.Title}");
                        break;
                    case Severity.Informational:
                        Program.Info($"{result.Title}");
                        break;
                    case Severity.Unknown:
                        Program.DarkGray($"{result.Title}");
                        break;
                    default:
                        throw new InvalidOperationException($"Unexpected severity value: {result.Severity}");
                }

                Program.DarkGray($"Identifier: {result.RuleIdentifier}");

                if (result.Path.Length > 0 || result.LineNumber != null || result.LinePosition != null)
                {
                    Program.DarkGray($"Line: {result.LineNumber}, Position: {result.LinePosition}, Path: {result.Path}");
                }

                Console.WriteLine(result.Description);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Writes a file results heading message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void DisplayFileResultsHeading(string content) => Program.WriteLine(content: content, color: ConsoleColor.Magenta);

        /// <summary>
        /// Writes a warning message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void Warning(string content) => Program.WriteLine(content: content, color: ConsoleColor.Yellow);

        /// <summary>
        /// Writes an error message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void Error(string content) => Program.WriteLine(content: content, color: ConsoleColor.Red);

        /// <summary>
        /// Writes a success message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void Success(string content) => Program.WriteLine(content: content, color: ConsoleColor.Green);

        /// <summary>
        /// Writes an informational message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void Info(string content) => Program.WriteLine(content: content, color: ConsoleColor.Blue);

        /// <summary>
        /// Writes an informational message to the console.
        /// </summary>
        /// <param name="content">The content.</param>
        public static void DarkGray(string content) => Program.WriteLine(content: content, color: ConsoleColor.DarkGray);

        /// <summary>
        /// Writes to the console with the specified foreground color.
        /// </summary>
        /// <param name="content">The content.</param>
        /// <param name="color">The foreground color.</param>
        private static void WriteLine(string content, ConsoleColor? color = null)
        {
            color ??= Console.ForegroundColor;
            Console.ForegroundColor = color.Value;
            Console.WriteLine(content);
            Console.ResetColor();
        }
    }
}
