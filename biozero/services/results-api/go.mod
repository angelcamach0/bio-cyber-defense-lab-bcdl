module biozero/results-api

go 1.22

require (
	biozero/artifact-executor v0.0.0
	biozero/enclave-runner v0.0.0
	biozero/ownership-authority v0.0.0
)

replace biozero/artifact-executor => ../artifact-executor
replace biozero/enclave-runner => ../enclave-runner
replace biozero/ownership-authority => ../ownership-authority
