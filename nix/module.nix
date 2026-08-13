self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.idrac6-kvm;
in
{
  options.services.idrac6-kvm = {
    enable = lib.mkEnableOption "iDRAC 6 KVM proxy (APCP to RFB/VNC)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.default;
      defaultText = lib.literalExpression "idrac6-kvm.packages.\${system}.default";
      description = "The idrac6-kvm package to run.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      description = "iDRAC hostname or IP address.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "iDRAC username used to mint the KVM session token.";
    };

    passwordFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to a file containing the iDRAC password (kept out of the store).";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:5900";
      description = "Address the RFB/VNC server listens on.";
    };

    novnc = {
      enable = lib.mkEnableOption "the optional noVNC browser frontend (noVNC + websockify)";
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:6080";
        description = "host:port the noVNC web endpoint listens on.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.idrac6-kvm =
      let
        runner = pkgs.writeShellScript "idrac6-kvm-run" ''
          export IDRAC_PASSWORD="$(cat "${cfg.passwordFile}")"
          exec ${lib.getExe cfg.package} serve \
            --host ${lib.escapeShellArg cfg.host} \
            --user ${lib.escapeShellArg cfg.user} \
            --listen ${lib.escapeShellArg cfg.listen}
        '';
      in
      {
        description = "iDRAC 6 KVM proxy";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = runner;
          DynamicUser = true;
          Restart = "on-failure";
          RestartSec = 5;
        };
      };

    systemd.services.idrac6-kvm-novnc = lib.mkIf cfg.novnc.enable {
      description = "noVNC frontend for idrac6-kvm";
      wantedBy = [ "multi-user.target" ];
      after = [ "idrac6-kvm.service" ];
      serviceConfig = {
        # websockify bridges the RFB TCP port to a browser-facing WebSocket + serves noVNC.
        ExecStart = ''
          ${pkgs.python3Packages.websockify}/bin/websockify \
            --web=${pkgs.novnc}/share/webapps/novnc \
            ${cfg.novnc.listen} ${cfg.listen}
        '';
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
