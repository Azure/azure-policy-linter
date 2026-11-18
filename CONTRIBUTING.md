# Contributing

## Build and package validation

Build with the .NET 10 SDK pinned in `global.json`. Libraries and CLIs target both `net8.0`
and `net10.0`; tests and the debugger run on .NET 10. Select `--framework net10.0` when
running the CLI project from source.

After building and packing both projects, run:

```powershell
.\scripts\TestPackages.ps1 -PackageDirectory <package-output-directory>
```

This checks both framework payloads and installs each CLI into a temporary, isolated tool
directory. It verifies automatic selection and execution of the .NET 10 asset. To test
customer compatibility, run it from a directory pinned to an installed .NET 8 SDK with
`-ExpectedFramework net8.0`. That optional compatibility check requires runtime 8; normal
builds and tests do not.

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