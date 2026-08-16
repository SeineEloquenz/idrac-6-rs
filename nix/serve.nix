self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.idrac6-kvm-serve;
in
{
  options.services.idrac6-kvm-serve = {
    enable = lib.mkEnableOption "iDRAC 6 KVM RFB/VNC proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix {
        pname = "idrac6-kvm-serve";
        blurb = "(RFB/VNC proxy)";
        src = self;
      };
      defaultText = lib.literalExpression "pkgs.callPackage \"\${idrac6-kvm}/nix/package.nix\" { pname = \"idrac6-kvm-serve\"; src = idrac6-kvm; }";
      description = "The idrac6-kvm package to run.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      description = "iDRAC hostname or IP address the console connects to.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "iDRAC account used to mint the KVM session.";
    };

    passwordFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing the iDRAC account password on a single line. Loaded as a
        systemd credential at runtime, so it never enters the Nix store or the process arguments.
        Point it at a sops/agenix-managed secret.
      '';
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:5900";
      description = ''
        host:port the RFB/VNC server listens on. The RFB server is unauthenticated (Security =
        None), so bind to localhost and reach it over an SSH tunnel, or bind only to a trusted
        network.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.idrac6-kvm-serve = {
      description = "iDRAC 6 KVM RFB/VNC proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        LoadCredential = [ "password:${cfg.passwordFile}" ];
        ExecStart = pkgs.writeShellScript "idrac6-kvm-serve-start" ''
          export IDRAC_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/password")"
          exec ${lib.getExe cfg.package} \
            --host ${lib.escapeShellArg cfg.host} \
            --user ${lib.escapeShellArg cfg.user} \
            --listen ${lib.escapeShellArg cfg.listen}
        '';
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
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        CapabilityBoundingSet = "";
        UMask = "0077";
      };
    };
  };
}
