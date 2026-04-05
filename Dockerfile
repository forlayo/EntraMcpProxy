FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["EntraMcpProxy.csproj", "."]
RUN dotnet restore "./EntraMcpProxy.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/publish \
    /p:SelfContained=false /p:PublishSingleFile=false /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "EntraMcpProxy.dll"]
