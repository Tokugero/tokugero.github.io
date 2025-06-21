{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
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
  ];

  # Set up a local GEM_HOME so you don't need sudo
  shellHook = ''
    export GEM_HOME="$PWD/.gems"
    export PATH="$GEM_HOME/bin:$PATH"
    echo "Ruby, Bundler, and system dependencies ready."
    echo "If first time, run: bundle config set --local path 'vendor/bundle'"
    echo "Then: bundle install"
    echo "Then: bundle exec jekyll serve"
  '';
}
