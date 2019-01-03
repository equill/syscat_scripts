with import <nixpkgs> {};

stdenv.mkDerivation rec {
    name = "webcat";

    buildInputs = let
    in [
        pkgs.python37Full
        python37Packages.pip
        python37Packages.virtualenv
    ];

    shellHook = "export PS1='\n\\[\\033[01;32m\\][nix syscat_discovery] \\w\\$\\[\\033[00m\\] '";

    env = buildEnv {
        name = name;
        paths = buildInputs;
    };
}
