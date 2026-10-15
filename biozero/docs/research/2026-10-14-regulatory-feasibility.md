# SCI01 — Viabilidad preliminar de Sei-LLRA

Fecha: 2026-10-14. Estado: **carga/inferencia entrenada verificada para un par sintético; piloto biológico pendiente**.

## Qué se comprobó

La revisión estática de Sei-LLRA se fijó al commit `217469410410e07b6663372da847426ffd172855` (2026-06-11), versión de paquete 1.5.9 según [pyproject.toml](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/pyproject.toml). El cacheversion de configuración es 1.5; son identificadores diferentes y no prueban incompatibilidad por sí solos. La configuración de CPU solicita `get_default_qconfig('fbgemm')` para tronco y head, sin fijar explícitamente el motor, en [get_models.py](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/src/get_models.py). Esto deja la ejecución ARM por comprobar; no demuestra un fallo inevitable.

Se reprodujo que una anotación `int | None` evaluada sin `from __future__ import annotations`, usada en [get_models.py](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/src/get_models.py), falla en Python 3.9. Se requiere Python >= 3.10 para ese código tal como está publicado. El preflight marca la ejecución pendiente cuando el Python local no cumple ese requisito.

La [licencia del código revisado](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/LICENSE.txt) es MIT. En la revisión inicial no se establecieron permisos específicos de los pesos, tamaños exactos de descargas ni hashes de esos archivos; el checkpoint posterior de adquisición aparece abajo. Los enlaces de descarga automáticos de Google Drive, gestionados por [download_from_gdrive.py](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/src/download_from_gdrive.py), no se descargaron para esta revisión.

Las estimaciones estáticas FP32 de parámetros son aproximadamente **320,389,300 bytes para rango 64** y **3,565,265,240 bytes para el modelo completo**, según el conteo estático a partir de las dimensiones de [sei_parts.py](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/src/sei_parts.py). No son tamaños de checkpoint ni RSS: no incluyen todas las estructuras, buffers, activaciones, temporales o sobrecarga de ejecución. No bastan para concluir que el modelo cabe en RAM.

## Evidencia de ejecución local

El [preflight](../../research/regulatory/preflight.py) no usa pesos ni red. El primer [reporte](../../research/regulatory/feasibility.json) detectó Python 3.9.25, arquitectura aarch64, un CPU lógico y 5,859,201,024 bytes de memoria del host; no detectó un límite cgroup efectivo adicional. No encontró distribución Torch. El resultado fue `pending` por Python < 3.10. Estos datos son una fotografía del runtime, no un requisito del proyecto.

Seis tests unitarios sin Torch pasaron: versión de Python incompatible, dependencia ausente, motor no soportado, fallo de ejecución, separación entre éxito sintético y compatibilidad de checkpoint, y separación qconfig/motor. Los tests usan dobles de dependencia; no reemplazan una ejecución real.

### Actualización ejecutada: runtime CPU aislado

El entorno observado se amplió con Python 3.11.17 y **Torch 2.14.1+cpu**, instalados únicamente en un prefijo aislado. La rueda CPU oficial mide 159,226,505 bytes; se comprobó su SHA256 publicado y sus dependencias antes de instalar. Se evitó la distribución CUDA, que no corresponde al hardware observado. El bootstrap conserva 26 paquetes con artefactos de conda-forge fijados y once ruedas con SHA256; se recreó un segundo entorno desde esos locks. Véanse [instalación oficial](https://pytorch.org/get-started/locally/), [índice CPU oficial](https://download.pytorch.org/whl/cpu/torch/) y [bootstrap](../../infra/bootstrap/regulatory-tools.sh).

La ejecución real del modelo pequeño sin entrenar dio:

| Configuración | Resultado observado | Evidencia |
| --- | --- | --- |
| Motor inicial de Torch `x86`, qconfig `fbgemm` | PASS: nueve checks, FP32/cuantización finitos, repetición y roundtrip idénticos | [feasibility.json](../../research/regulatory/feasibility.json) |
| Motor explícito `qnnpack`, mismo qconfig `fbgemm` | PASS: los mismos nueve checks | [alternativa](../../research/regulatory/qnnpack-fbgemm-feasibility.json) |
| Motor forzado `fbgemm` | FAIL: RuntimeError `unknown architecure` | [fallo preservado](../../research/regulatory/fbgemm-forced-feasibility.json) |

Solicitar `get_default_qconfig('fbgemm')` no selecciona el motor FBGEMM. El código Sei fijado no fuerza ese motor; el preflight ahora conserva el motor inicial por defecto y registra ambos valores por separado. El fallo del motor forzado no permite declarar incompatible el camino original de Sei. Los éxitos tampoco prueban compatibilidad del checkpoint, velocidad o exactitud científica: **esas condiciones siguen pendientes**.

## Gates para avanzar

1. **Runtime:** Python >= 3.10 y Torch importable; registrar versiones, arquitectura, motores y diagnóstico del preflight. Un fallo sintético necesita corregirse o reproducirse con un backend apropiado antes de atribuir compatibilidad al camino CPU.
2. **Artefactos:** identificar pesos exactos, permisos de uso, tamaños y hashes; verificar procedencia y condiciones de uso. La licencia MIT del código no resuelve la licencia de los pesos.
3. **Recursos:** fijar un techo de memoria y tiempo antes de ejecutar un checkpoint real; medir RSS máximo y duración. El conteo de parámetros no sustituye esa medición.
4. **Compatibilidad real:** cargar un checkpoint identificable y ejecutar bloques secuenciales de 1, 10 y 100 pares de entradas. Registrar versión, configuración, hashes, salidas finitas y fallos. Un preflight sintético aprobado no satisface este gate.
5. **Evaluación:** distinguir referencia FP32 de verdad científica. FP32 sirve como comparador de estabilidad numérica; la exactitud biológica requiere datos y etiquetas válidos para la pregunta elegida.
6. **Economía:** medir `t_cheap + t_gate + r * t_full < t_full` sobre la misma carga, donde `r` es fracción enviada al cálculo completo. Mantener también un criterio de calidad predefinido: menor tiempo sin calidad suficiente no cumple el objetivo.

No se declara viabilidad, ventaja de costo ni compatibilidad ARM mientras falten estas pruebas. El preflight de operadores ya se ejecutó. La carga/inferencia entrenada ya se ejecutó. La siguiente operación científica es congelar datos/contexto/track y validar un baseline FP32 pequeño antes de ampliar a 100 pares; no ampliar la puerta cuantizada actual por inercia.

## Fuentes primarias fijadas

- [Árbol Sei-LLRA fijado](https://github.com/kostkalab/seillra/tree/217469410410e07b6663372da847426ffd172855): identidad de la revisión.
- [model_loading.py](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/src/model_loading.py): camino de carga a revisar antes del piloto con checkpoints.
- [FBGEMM oficial](https://github.com/pytorch/FBGEMM) y [QNNPACK oficial](https://github.com/pytorch/QNNPACK): contexto de backends. Estos repositorios no prueban compatibilidad de un modelo concreto con este runtime.

Las fuentes de Sei fueron inspeccionadas; una revisión independiente verificó también pyproject.toml. La consulta web independiente a LICENSE.txt expiró y el árbol src no fue accesible por ese canal, por lo que esas afirmaciones se basan en la primera inspección estática y no en una segunda comprobación. El commit fijado es el identificador de referencia; una rama main mutable no sustituye esa evidencia.

## Checkpoint de adquisición de pesos

Se leyó la [configuración fijada](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/dist/seillra/dat/config.yaml) y se midieron tamaños mediante HEAD; los SHA publicados proceden de sus sidecars. Posteriormente se descargaron los cinco componentes con [checkpoint_fetch.py](../../research/regulatory/checkpoint_fetch.py) y se comprobaron por separado los tamaños y hashes sobre los archivos locales. Total verificado: **400,312,985 bytes**, incluidos troncos y cabezas rank-64 FP32/CPU y una proyección FP32 compartida. [Manifiesto fijado](../../research/regulatory/checkpoints.json) y [evidencia de adquisición](../../research/regulatory/checkpoint-acquisition.json).

El primer intento consumió 34,020,705 bytes observados y falló a los 180 segundos; la reserva interrumpida se conservó. El registro por ventanas redujo los fsync repetidos por fragmento y el reintento manual completó los cinco archivos. Cargo acumulado conservador: **435,387,199 bytes**, bajo el límite de 1 GiB, sin reset del ledger. Esta observación valida adquisición íntegra; no acredita aún carga ni inferencia del modelo entrenado.

La licencia [MIT del código Sei-LLRA](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/LICENSE.txt), la licencia del [software original FunctionLab](https://github.com/FunctionLab/sei-framework/blob/main/LICENSE.txt) y los permisos del modelo son distintos. El [registro original Zenodo 4906997](https://zenodo.org/records/4906997) y su [API](https://zenodo.org/api/records/4906997) identifican el modelo original como CC-BY-4.0 y abierto; su archivo de 3.28 GB no se descargó. No se verificó una declaración independiente de distribución para los archivos Drive derivados. Los componentes adquiridos se conservan privados para investigación interna; no se redistribuyen pesos ni datos de entrenamiento.

## Ejecución entrenada y decisión de recursos

Se ejecutó rango 64 con state_dicts locales estrictos, weights_only=True,
batch uno, un hilo y ambas orientaciones del wrapper fijado. La carga, salidas
finitas, forma, repetición idéntica y presupuestos pasaron. Una revisión independiente leyó los reportes
y verificó el mismo hash de entrada. Las nuevas corridas FP32/QNNPACK fueron
secuenciales en namespaces que solo contenían loopback; la anterior usó factories
bloqueadas sin aislamiento de red del kernel.
[Evidencia agregada](../../research/regulatory/runtime-feasibility.json).

| Configuración | Tiempo medido por par | Pico RSS |
| --- | ---: | ---: |
| FP32, namespace sin red | 11.2743 s | 953,081,856 B |
| CPU QNNPACK, namespace sin red | 18.7719 s | 957,833,216 B |
| CPU motor inicial x86, corrida anterior | 77.8412 s | 1,192,751,104 B |

El techo fue 3 GiB con vigilancia RSS cada 50 ms y pico reportado por el hijo,
120 s por fase y tiempo total finito; no es un límite de asignación del kernel.
Nueve tests reales de supervisión pasaron, junto con once de adquisición y seis
del preflight: 26 pruebas en esta carpeta. Ningún test con dobles acredita biología.

QNNPACK fue 1.665 veces más lento que FP32 para ese par. Incluso con coste cero
de puerta, T_cuantizado + r*T_FP32 < T_FP32 exigiría r < -0.665, imposible para
una fracción no negativa. Decisión: **GO de compatibilidad para la entrada medida;
NO-GO económico provisional de la puerta actual en esta configuración**.
Es una observación de un par sintético, no una conclusión universal sobre datos
biológicos, cuantización ni otras máquinas.

La diferencia máxima/media de variant_delta QNNPACK frente al nuevo FP32 fue
0.0405562/0.0101628; la anterior x86 fue 0.0554321/0.0054822. Son desacuerdos
numéricos sobre 61 clases proyectadas, no 61 casos independientes ni medidas de
exactitud biológica. No está demostrado que una salida sea mejor.

El [protocolo SCI02 propuesto](../experiments/002-regulatory-biological-baseline.md)
preserva el objetivo de 100 pares biológicos con validación previa de diez loci
FP32. La cabeza de 21,907 tracks debe dar una salida compatible con el ensayo;
las clases proyectadas no se convierten en etiquetas ATAC/DNase por renombrarlas.
