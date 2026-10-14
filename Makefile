.PHONY: test bio-tools science experiment experiment-soc regulatory-tools regulatory-preflight

BIOZERO_TOOLS_PREFIX ?= $(CURDIR)/.biozero/bio-tools
BIOZERO_REGULATORY_PREFIX ?= $(CURDIR)/.biozero/regulatory

test:
	python3 -m unittest discover -s biozero/bio/pipeline -p 'test_*.py'
	python3 -m unittest discover -s biozero/bio/benchmarks -p 'test_*.py'
	python3 -m unittest discover -s biozero/infra/native -p 'test_*.py'
	python3 -m unittest discover -s biozero/infra/compose -p 'test_*.py'
	python3 -m unittest discover -s biozero/infra/soc -p 'test_*.py'
	python3 -m unittest discover -s biozero/research/regulatory -p 'test_*.py'
	python3 -B biozero/infra/native/check_go.py

bio-tools:
	BIOZERO_TOOLS_PREFIX="$(BIOZERO_TOOLS_PREFIX)" bash biozero/infra/bootstrap/bio-tools.sh

science:
	PATH="$(BIOZERO_TOOLS_PREFIX)/bin:$$PATH" python3 biozero/bio/benchmarks/run_variant_smoke.py --out-dir biozero/docs/evidence/science

experiment:
	python3 -B biozero/infra/native/run_experiment.py --tools-prefix "$(BIOZERO_TOOLS_PREFIX)"

experiment-soc:
	python3 -B biozero/infra/native/run_experiment.py --soc --tools-prefix "$(BIOZERO_TOOLS_PREFIX)"

regulatory-tools:
	BIOZERO_REGULATORY_PREFIX="$(BIOZERO_REGULATORY_PREFIX)" bash biozero/infra/bootstrap/regulatory-tools.sh

regulatory-preflight:
	"$(BIOZERO_REGULATORY_PREFIX)/bin/python" biozero/research/regulatory/preflight.py
