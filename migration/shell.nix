with import <nixpkgs> {};

stdenv.mkDerivation rec {
    name = "syscat_migration";

    buildInputs = [
        pkgs.python37Full
        pkgs.python37Packages.pip
        pkgs.python37Packages.virtualenv
    ];

    env = buildEnv {
        name = name;
        paths = buildInputs;
    };

    shellHook = "export PS1='\n\\[\\033[01;32m\\][nix syscat migration] \\w\\$\\[\\033[00m\\] ';\
                 export PYTHONPATH=$PWD/venv/lib/python3.7/site-packages/:$PYTHONPATH;
                 unset SOURCE_DATE_EPOCH";

}
