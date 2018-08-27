with import <nixpkgs> {};

stdenv.mkDerivation rec {
    name = "syscat";

    buildInputs = [
        pkgs.python36Packages.requests
        pkgs.python36Packages.pylint
        pkgs.python3
        pkgs.bash
    ];

    env = buildEnv {
        name = name;
        paths = buildInputs;
    };
}
