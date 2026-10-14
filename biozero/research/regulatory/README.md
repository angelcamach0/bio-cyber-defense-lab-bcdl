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
