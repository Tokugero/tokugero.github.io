{
  description = "Jekyll dev shell for tokugero.github.io";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.ruby
            pkgs.bundler
            pkgs.git
            pkgs.zlib
            pkgs.libffi
            pkgs.makeWrapper
            pkgs.gcc
            pkgs.pkg-config
            pkgs.libyaml
            pkgs.openssl
            pkgs.nodejs
            pkgs.playwright-driver.browsers
          ];

          shellHook = ''
            export GEM_HOME="$PWD/.gems"
            export PATH="$GEM_HOME/bin:$PATH"
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

            # Auto-install bundle dependencies
            if [ ! -d vendor/bundle ]; then
              echo "First time setup: installing bundle dependencies..."
              bundle config set --local path 'vendor/bundle'
              bundle install --quiet
            fi

            # Auto-install playwright node module (pinned to match Nix browsers)
            PLAYWRIGHT_NIX_VERSION=$(node -e "console.log(require('$(dirname $(which playwright))/../lib/node_modules/playwright-core/package.json').version)" 2>/dev/null || echo "")
            if [ -n "$PLAYWRIGHT_NIX_VERSION" ]; then
              CURRENT_PW_VERSION=$(node -e "try{console.log(require('playwright-core/package.json').version)}catch(e){}" 2>/dev/null || echo "")
              if [ "$CURRENT_PW_VERSION" != "$PLAYWRIGHT_NIX_VERSION" ]; then
                echo "Installing playwright@$PLAYWRIGHT_NIX_VERSION (matching Nix browsers)..."
                npm install --no-save "playwright@$PLAYWRIGHT_NIX_VERSION" 2>/dev/null
              fi
            fi

            echo "Dev environment ready. Run: bundle exec jekyll serve"
          '';
        };
      }
    );
}
