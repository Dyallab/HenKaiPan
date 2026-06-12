{
  description = "HenKaiPan ASPM platform: security scans, findings, knowledge articles, AI-assisted remediation";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        version = if self ? shortRev then self.shortRev else "dev";
        buildDate = "unknown";

        ldflags = [
          "-X"
          "aspm/internal/handlers.Version=${version}"
          "-X"
          "aspm/internal/handlers.BuildDate=${buildDate}"
        ];
        ldflags_str = builtins.concatStringsSep " " ldflags;

        mkShellApp = name: script: rec {
          type = "app";
          program = "${pkgs.writeShellScriptBin "aspm-${name}" script}/bin/aspm-${name}";
        };

        mkGoBinary =
          pname: sub:
          pkgs.buildGoModule {
            pname = "aspm-${pname}";
            inherit version;
            src = ./.;
            vendorHash = "sha256-TZJki/mfnAbAoDMGnEJNyk4bMahsf6qsvSlHNzFb4Ag=";
            ldflags = ldflags;
            subPackages = [ "cmd/${sub}" ];

            meta = {
              description = "HenKaiPan ${pname} binary";
              homepage = "https://github.com/dyallab/HenKaiPan-app";
              license = pkgs.lib.licenses.mit;
              maintainers = ["jd-apprentice"];
              mainProgram = pname;
            };
          };

        mkFull = pkgs.stdenv.mkDerivation {
          pname = "aspm-full";
          inherit version;
          src = ./.;

          nativeBuildInputs = with pkgs; [
            go
            nodejs_24
            pnpm
          ];

          buildPhase = ''
            export HOME=$TMPDIR

            pushd frontend
            pnpm install --frozen-lockfile
            pnpm build
            popd

            mkdir -p cmd/api/frontend-dist
            cp -r frontend/dist/. cmd/api/frontend-dist/

            go build \
              -tags embed_frontend \
              -ldflags="${ldflags_str}" \
              -o api ./cmd/api \

            go build \
              -ldflags="${ldflags_str}" \
              -o worker ./cmd/worker

            go build \
              -ldflags="${ldflags_str}" \
              -o bot ./cmd/bot
          '';

          installPhase = ''
            mkdir -p $out/bin
            cp api worker bot $out/bin/
          '';

          meta = {
            description = "HenKaiPan full build (API + worker + bot with embedded frontend)";
            homepage = "https://github.com/dyallab/HenKaiPan-app";
            license = pkgs.lib.licenses.mit;
            maintainers = ["jd-apprentice"];
          };
        };
      in
      {
        packages = {
          api = mkGoBinary "api" "api";
          worker = mkGoBinary "worker" "worker";
          bot = mkGoBinary "bot" "bot";
          full = mkFull;
          default = self.packages.${system}.api;
        };

        devShells.default = pkgs.mkShell {
          packages =
            with pkgs;
            [
              go
              gopls
              gotools
              go-tools
              golangci-lint
              air
              garble
              nodejs_24
              pnpm
              postgresql_17
              redis
              jq
            ];

          shellHook = ''
            echo "━━━ HenKaiPan Dev Shell ━━━"
            echo "  go:    $(go version 2>/dev/null)"
            echo "  node:  $(node --version 2>/dev/null)"
            echo "  pnpm:  $(pnpm --version 2>/dev/null)"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
          '';
        };
      }
    );
}
