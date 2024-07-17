#!/bin/bash

# Naviga nella directory singlefile-FS ed esegue i comandi make
cd singlefile-FS || { echo "Directory singlefile-FS non trovata"; exit 1; }
make all
make load
make create
make mnt

# Torna alla directory principale e naviga nella directory user
cd ..
cd user || { echo "Directory user non trovata"; exit 1; }

# Esegue make clean e make
make clean
make

# Torna alla directory principale
cd ..

# Esegue make clean, git pull, make e make mount nella directory principale
make clean
git pull
make
make mount
