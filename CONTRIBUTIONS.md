# Contributing

At this moment we are not accepting contributions. However, if we do, most contributions require you
to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually
do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

We always welcome issues and suggestions from the community. Please open an issue to propose new
rules, suggest improvements to existing rules, or report bugs and other problems you find.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a
CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Local build, pack, and run

Requires the .NET SDK version pinned in [global.json](global.json).

To open the repository in an editor, use the helper scripts at the repo root:
- `vs.cmd` - restores packages, generates `dirs.sln` via slngen, and opens Visual Studio. Pass `--no-launch` to generate the solution without opening Visual Studio.
- `vsc.cmd` - restores packages, generates `dirs.sln` via slngen, and opens the repository in Visual Studio Code. The C# Dev Kit extension uses the solution file to load the full project structure.

Build the solution:

```
dotnet build src/dirs.proj --configuration Release
```

Run the CLI directly from source:

```
dotnet run --project src/PolicyLinter.Cli -- <path-to-policy-json>
```

Run the tests:

```
dotnet test src/Tests/PolicyLinter.Tests/PolicyLinter.Tests.csproj
```

To pack the CLI and install it as a global .NET tool (so you can invoke `policylinter` directly). Run these from the repository root:

1. Uninstall any existing global install first - the local install will fail otherwise:
   ```
   dotnet tool uninstall -g Azure.Policy.PolicyLinter.Cli
   ```

2. Publish the CLI to the output path the nuspec packs from:
   ```
   dotnet publish src/PolicyLinter.Cli/PolicyLinter.Cli.csproj --configuration Release -o out/retail-AMD64/PolicyLinter.Cli
   ```

3. Pack. The nuspec's file paths are resolved relative to `NuspecBasePath`, which must be an absolute path, so pass the repo root via `$PWD` (PowerShell or bash; use `%CD%` in cmd):
   ```
   dotnet pack src/PolicyLinter.Cli/PolicyLinter.Cli.csproj -p:NuspecFile=$PWD/src/PolicyLinter.Cli/PolicyLinter.Cli.nuspec -p:NuspecBasePath=$PWD -o <output-path>
   ```

4. Install from the local output:
   ```
   dotnet tool install -g Azure.Policy.PolicyLinter.Cli --add-source <output-path> --no-cache
   ```

5. Run:
   ```
   policylinter <path-to-policy-json>
   ```

## Adding a linter rule

- [docs/linter-rule-design.md](docs/linter-rule-design.md) - what a good rule looks like (scope, severity, naming, description).
- [docs/linter-architecture.md](docs/linter-architecture.md) - how rules are wired up in the code.
- [.github/skills/triage-linter-rule/](.github/skills/triage-linter-rule/) - interactive skill to turn an idea into a spec.
- [.github/skills/implement-linter-rule/](.github/skills/implement-linter-rule/) - interactive skill to implement a rule from a spec.
- Every rule should have a doc file in [docs/Rules/](docs/Rules/) and at least one unit test.