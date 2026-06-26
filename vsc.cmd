@echo off

REM Restores packages, generates dirs.sln via slngen, and opens the repository in Visual Studio Code.
REM The C# Dev Kit extension uses the solution file to load the full project structure.

pushd "%~dp0"

if exist dirs.sln del /q dirs.sln

echo Restoring dotnet tools
dotnet tool restore

echo Restoring NuGet packages
dotnet restore src\dirs.proj --configfile NuGet.config

echo Generating dirs.sln
dotnet tool run slngen src\dirs.proj --folders true --solutionfile dirs.sln --launch false

echo Launching Visual Studio Code
code .

popd
