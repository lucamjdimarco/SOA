# SOA-Project

Specifiche del progetto raggiungibili al seguente link: https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html

## Deployment

Per eseguire il deployment del monitor è possibile eseguire il file bash ```start.sh```: esso compilerà sia il monitor e le sue librerie, sia il filesystem, sia la directory per l'esecuzione lato user. Successivamente caricherà ed installerà tutti i moduli necessari:

```bash
 ./start.sh
```
Per smontare completamente il deployment sopra costruito eseguire il file ```stop.sh```: esso rimuoverà tutti i file precedentemente compilati ed installati:
```bash
 ./stop.sh
```
Per caricare solamente il Reference Monitor, eseguire il file ```load.sh```. Per rimuovere solamente il Reference Monitor, eseguire il file ```unload.sh```.
```bash
 ./load.sh
```
```bash
 ./unload.sh
```

## Interazione user con il monitor
> [!WARNING]
> Il sistema, al suo avvio, presenterà una password iniziale pari a "default".

Le operazioni possibili da effettuare verso il Monitor sono le seguenti:

- Modifica della modalità di esecuzione del monitor (ON, OFF, REC_ON, REC_OFF);
- Cambio della password;
- Inserimento di un nuovo path da proteggere;
- Rimozione di un path da proteggere.

Per eseguire in maniera interattiva le precedenti operazioni illustrate, eseguire il file ```user``` presente nella cartella ```user/```:
```bash
 ./user
```
Nel'inserimento della password nel programma user, questa non verrà mostrata, emulando il comportamento dell'inserimento password del sistema Linux. Il suo valore comunque verrà preso e gestito.
