# Enviral

This repository contains the source code for the EuroSec'23 paper "Enviral: Fuzzing the Environment for Evasive Malware Analysis" by Floris Gorter, Cristiano Giuffrida, and Erik van der Kouwe.
The paper is available for download [here](https://download.vusec.net/papers/enviral_eurosec23.pdf).

### DLL
This gets injected into the target program to insert the system call hooks.

### Launcher
This repeatedly launches the target application and communicates with the injected code to insert and generate mutations.
