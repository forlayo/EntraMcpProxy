FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:8c0b6857eab7b2aa57884c839bf4678414606bd7d17370f18a842ac5cf414711 AS base
WORKDIR /app
EXPOSE 8080
USER $APP_UID

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:c0790639332692a0d56cdd81ed581cfd24d040d9839764c138994866df89a3b6 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Directory.Packages.props", "."]
COPY ["Directory.Build.props", "."]
COPY ["EntraMcpProxy.csproj", "."]
COPY ["packages.lock.json", "."]
RUN dotnet restore "./EntraMcpProxy.csproj" --locked-mode
COPY . .
RUN dotnet build "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/build --no-restore

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./EntraMcpProxy.csproj" -c $BUILD_CONFIGURATION -o /app/publish \
    --no-restore /p:SelfContained=false /p:PublishSingleFile=false /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish --chown=$APP_UID:$APP_UID /app/publish .
ENTRYPOINT ["dotnet", "EntraMcpProxy.dll"]
