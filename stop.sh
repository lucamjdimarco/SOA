#!/bin/bash

# Naviga nella directory singlefile-FS ed esegue i comandi make
cd singlefile-FS || { echo "Directory singlefile-FS non trovata"; exit 1; }
make clean
make remove

# Torna alla directory principale e naviga nella directory user
cd ..
cd user || { echo "Directory user non trovata"; exit 1; }

# Esegue make clean
make clean

# Torna alla directory principale
cd ..

# Esegue make clean e make unmount nella directory principale
make unmount
make clean
