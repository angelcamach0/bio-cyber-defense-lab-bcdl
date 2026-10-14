# SCI01: preflight regulatorio sin pesos

Este preflight inspecciona Python, CPU, memoria y Torch local. Si el runtime es compatible, ejecuta un modelo **sintético, sin entrenar** con Conv1d y Linear mediante cuantización FX. No descarga archivos, no carga checkpoints de Sei y no mide precisión científica.

```bash
python3 biozero/research/regulatory/preflight.py
python3 -m unittest discover -s biozero/research/regulatory -p test_preflight.py -v
```

Para registrar evidencia, usar el Python del entorno aislado que tenga Torch instalado:

```bash
/ruta/al/entorno/bin/python biozero/research/regulatory/preflight.py --output biozero/research/regulatory/feasibility.json
```

El script no instala dependencias. `make regulatory-tools` recrea el entorno CPU medido en Linux ARM64, con 26 paquetes de Python fijados y once ruedas verificadas por SHA256; no descarga pesos entrenados. `make regulatory-preflight` ejecuta el preflight en ese entorno. Python < 3.10 o Torch ausente producen `synthetic_probe.status=pending`; el código de salida 0 significa que el reporte se generó, **no** que la prueba pasó. Una ejecución sintética fallida devuelve 1. La salida JSON es la fuente del resultado.

La prueba usa semilla 20261014, un hilo y entrada local finita `[4,4,32]`. Comprueba salidas FP32/cuantizadas finitas, presencia de operadores cuantizados Conv1d y Linear, repetición idéntica y reproducción tras serializar/restaurar `state_dict` en memoria. Informa motores declarados, motor inicial/efectivo y qconfig. Por defecto `--engine current --qconfig fbgemm` conserva el motor inicial de Torch, como el código Sei revisado: solicitar un qconfig no selecciona el motor. Restaura motor, hilos y RNG al terminar. Los motores declarados no garantizan que todos sus operadores funcionen.

`--engine qnnpack --qconfig fbgemm` cambia solo el motor de ejecución. `--engine fbgemm --qconfig fbgemm` fuerza FBGEMM. En Python 3.11.17/Torch 2.14.1+cpu ARM, el motor inicial `x86` y el alternativo `qnnpack` pasaron los nueve checks; forzar `fbgemm` falló con `unknown architecure`. Son resultados de operadores sintéticos, no de Sei entrenado. Los tres JSON conservan esta diferencia.

Un `passed` solo permite afirmar que **esa pequeña operación sintética** funcionó en el runtime registrado. `checkpoint_compatibility` y `scientific_feasibility` permanecen `pending` incluso si pasa. No se mide RSS, velocidad del modelo Sei, compatibilidad de sus pesos, precisión regulatoria ni ahorro económico.

La memoria registrada distingue memoria del host y límite cgroup detectado; el techo efectivo es el menor límite conocido, no memoria disponible ni garantía contra OOM. Los tests unitarios usan dobles de Torch para probar clasificación de estados: no reemplazan la ejecución sintética real.

El reporte de referencia y los gates de investigación se describen en [el informe SCI01](../../docs/research/2026-10-14-regulatory-feasibility.md).

## Checkpoints reales y siguiente gate

Los cinco componentes rank-64 FP32/CPU se adquirieron y verificaron por tamaño
y SHA256; véase [checkpoint-acquisition.json](checkpoint-acquisition.json).
El downloader guarda checkpoints y ledger privados en .biozero/regulatory-assets,
separados del entorno Python .biozero/regulatory. Cuenta intentos fallidos,
reserva ventanas acotadas y nunca reinicia el presupuesto de 1 GiB. El primer
intento falló a los 180 segundos; una corrección del accounting por ventanas
permitió completar los cinco sin relajar tamaño, digest ni deadline.
No se incluyen los pesos en Git, Pages ni la evidencia compartida.

La carga entrenada estricta y la inferencia repetida de un par sintético ya pasaron;
la [evidencia agregada](runtime-feasibility.json) conserva tiempos, RSS, digests y
límites. Los reportes con vectores quedan privados. FP32/QNNPACK se compararon
secuencialmente en namespaces sin red: 11.27 y 18.77 s por par, respectivamente.
El backend cuantizado predeterminado había medido 77.84 s. La puerta actual tiene
un no-go económico provisional para ese caso; compatibilidad no equivale a ahorro.

Para repetir una prueba de recursos (sin confundirla con validación biológica):

```bash
make regulatory-tools
git clone https://github.com/kostkalab/seillra.git .biozero/seillra
git -C .biozero/seillra checkout 217469410410e07b6663372da847426ffd172855
python3 biozero/research/regulatory/checkpoint_fetch.py --download
unshare --user --map-root-user --net .biozero/regulatory/bin/python \
  biozero/research/regulatory/model_probe.py --run --pairs 1 --variant both --engine qnnpack
```

Las pruebas de supervisión usan procesos reales para timeout, RSS, señales,
protocolo y ausencia de artefactos; no acreditan inferencia con esos dobles.
El probe vigila RSS cada 50 ms y el pico reportado por el hijo, con techo de 3 GiB,
120 s por fase y tiempo total finito. No es un límite de asignación del kernel.
El comando unshare requiere soporte de namespaces; fallar no autoriza cambiar
políticas del host. La prueba no instala paquetes, descarga pesos automáticamente
ni invoca torch.compile. Su estado científico permanece pendiente incluso con PASS.

Seleccionar datos/contexto válidos y un track compatible de la cabeza es el próximo
gate. Cien pares sintéticos no reemplazan el piloto de 100 pares biológicos;
las 61 clases proyectadas tampoco equivalen a etiquetas ATAC/DNase experimentales.

## SCI02: normalized real-window adapter

`biological_adapter.py` accepts a normalized local case ledger, not an assumed
DART TSV schema. `baseline-protocol.json` fixes the source, FP32 rank 64 head,
21,907 outputs, nine GM12878 ATAC-seq tracks, ALT-minus-REF probability score,
deterministic disjoint-window selection and zero/tie metric rules. It disables
the 61-class projection and reuses the pinned both-strands forward.

Source bytes/digests, permitted usage, reviewed schema/effect semantics and the
normalization/selection snapshots must be verified before biological inference.
The submitted payload must equal its frozen normalized row, including effects
and provenance. Evaluation of 100 requires a passed biological 10-locus adapter
receipt with matching dataset/protocol/weights/selection; an instrumentation
control cannot satisfy that prerequisite. Disjoint windows do not guarantee
independence under linkage disequilibrium. Every submitted row remains recorded.

Prepare the fixed public UCSC reference/artificial-C-to-G control:

```bash
# Cached acquisition by default; --fetch explicitly permits one bounded HTTPS read.
python3 biozero/research/regulatory/control_fixture.py --fetch
python3 biozero/research/regulatory/biological_adapter.py \
  --ledger .biozero/regulatory-assets/datasets/control-case-ledger.json --validate-only
unshare --user --map-root-user --net .biozero/regulatory/bin/python \
  biozero/research/regulatory/biological_adapter.py \
  --ledger .biozero/regulatory-assets/datasets/control-case-ledger.json \
  --python .biozero/regulatory/bin/python --run
```

Use the already-created pinned source/checkpoint cache described above. The
control source has 4,096 bases and a fixed DNA SHA; HTTP metadata timestamps can
change, so each cache records its own source-byte digest. No fetch happens when
that validated cache exists. Existing outputs are never replaced with different
bytes. Redirects, symlinks, FIFOs, oversize responses and mismatched reference
metadata are rejected. No checkpoint download is part of the adapter.

`--validate-only` uses no Torch and records input readiness separately from
inference. `--run` supervises a separate CPU process with a 3 GiB RSS watchdog,
120 s per phase, one thread and batch one. Atomic private progress preserves
completed rows if execution fails; remaining cases are marked failed. The
watchdog is not a kernel allocation cap. Prediction vectors and full case reports
stay private. A control PASS leaves biological feasibility pending: its ALT is
artificial and it has no experimental effect label. Actual ten/hundred-locus
measurements remain pending authorized data and the frozen scientific protocol.

## Small public caQTL source: acquisition and descriptive inspection

The Kumasaka/Knights/Gaffney [Zenodo record1405945](https://zenodo.org/records/1405945)
provides an open CC-BY-4.0 alternative source. The complete lead-variant gzip
and README were acquired with their published size/MD5 and new SHA256 pins.
See [acquisition receipt](small-source-acquisition.json),
[structure receipt](small-source-structure.json) and
[source investigation](../../docs/research/2026-10-14-small-caqtl-sources.md).
This is not a copy of the inaccessible Synapse DART v2 file.

Use the existing private cache without another transfer:

```bash
python3 -B biozero/research/regulatory/small_dataset_fetch.py \
  --prefix .biozero/regulatory-assets
python3 -B biozero/research/regulatory/inspect_small_source.py \
  --source .biozero/regulatory-assets/datasets/lead_caQTL_variants.tsv.gz
```

A fresh installation may add `--fetch` to the first command for the fixed public
files. The separate persistent50MiB dataset ledger includes the earlier4,251-byte
UCSC control and retains failed/partial charges. Current charge is10,512,921 bytes;
the checkpoint ledger remains435,387,199 bytes. Never remove/reset ledgers to
repeat downloads over retained data. Raw files, source rows and model vectors
stay private; the two linked receipts export only descriptive metadata/counts.

Complete gzip/CRC inspection found297,308 rows and29,004,438 expanded bytes under
the512MiB expansion/8,192-byte line limits. The source is GRCh37 population LCL
caQTL, while the frozen model protocol uses hg38/GM12878 tracks. Header aliases,
one-based coordinates, focal-peak mapping, Beta/ALT orientation, liftover/strand/
REF checks, context, training overlap and the ten/100 split still require a
reviewed normalization freeze before inference. These descriptive counts are
not selected biological cases. Zero experimental loci have been scored.
