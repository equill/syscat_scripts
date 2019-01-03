with import <nixpkgs> {};

stdenv.mkDerivation rec {
    name = "syscat";

    buildInputs = [
        pkgs.python36Packages.requests
        pkgs.python36Packages.pylint
        pkgs.python3
        pkgs.bash
    ];

    shellHook = "export PS1='\n\\[\\033[01;32m\\][nix webcat] \\w\\$\\[\\033[00m\\] '";

    env = buildEnv {
        name = name;
        paths = buildInputs;
    };
}
