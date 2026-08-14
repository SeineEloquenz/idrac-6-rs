self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.idrac6-kvm-serve;
in
{
  options.services.idrac6-kvm-serve = {
    enable = lib.mkEnableOption "iDRAC 6 KVM RFB/VNC proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.serve;
      defaultText = lib.literalExpression "idrac6-kvm.packages.\${system}.serve";
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
          exec ${lib.getExe cfg.package} serve \
            --host ${lib.escapeShellArg cfg.host} \
            --user ${lib.escapeShellArg cfg.user} \
            --listen ${lib.escapeShellArg cfg.listen}
        '';
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
