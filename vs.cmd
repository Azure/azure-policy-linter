@echo off

REM Re-creates the solution file and launches Visual Studio.
REM Pass --no-launch to generate the solution without opening Visual Studio.

if exist dirs.sln del /q dirs.sln

echo Restoring dotnet tools
dotnet tool restore

echo Restoring NuGet packages
dotnet restore src\dirs.proj --configfile NuGet.config

echo Generating dirs.sln
if "%~1" neq "--no-launch" (
    dotnet tool run slngen src\dirs.proj --folders true --solutionfile dirs.sln
) else (
    dotnet tool run slngen src\dirs.proj --folders true --solutionfile dirs.sln --launch false
)
