self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.idrac6-kvm-web;
in
{
  options.services.idrac6-kvm-web = {
    enable = lib.mkEnableOption "iDRAC 6 KVM web console (browser login + noVNC)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.web;
      defaultText = lib.literalExpression "idrac6-kvm.packages.\${system}.web";
      description = "The idrac6-kvm package to run (must include the `web` feature).";
    };

    host = lib.mkOption {
      type = lib.types.str;
      description = "iDRAC hostname or IP address the console connects to.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "Username pre-filled on the login form.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      description = ''
        host:port the web UI listens on. Plain HTTP — the iDRAC credentials are entered in the
        browser, so bind to localhost and put a TLS reverse proxy in front, or bind only to a
        trusted network.
      '';
    };

    novncPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.novnc;
      defaultText = lib.literalExpression "pkgs.novnc";
      description = "noVNC package whose web assets are served to the browser.";
    };

    idleTimeout = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 600;
      description = "Release the KVM session after this many seconds with no connected viewer.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.idrac6-kvm-web = {
      description = "iDRAC 6 KVM web console";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "--host" cfg.host
          "--user" cfg.user
          "--listen" cfg.listen
          "--novnc-root" "${cfg.novncPackage}/share/webapps/novnc"
          "--idle-timeout" (toString cfg.idleTimeout)
        ];
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        CapabilityBoundingSet = "";
        UMask = "0077";
      };
    };
  };
}
