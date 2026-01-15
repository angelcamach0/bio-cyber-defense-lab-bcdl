# MVP Evidence Log Updates

Populate these entries as you run the tests.

- IMG_30: Successful upload response with job_id.
- LOG_30: Runner output showing processed job and result write.
- IMG_31: Results API response with processed JSON.
- LOG_31: TLS failure when client cert is missing.
- LOG_32: Runner result showing decrypted=true.
- LOG_33: Runner result showing signature_valid=true.
- IMG_34: Results API 403 for incorrect client identity.
- IMG_35: ZeroResponder /alert HTTP 200 response.
- LOG_34: ZeroResponder actions.log entry for alert.
- CONF_10: TLS config (server cert, CA bundle paths).

## Captured Evidence (2026-01-13)
- LOG_30_uploader_cli.txt: Upload + results output (job_id `d846d14ae9491894`, decrypted=true, signature_valid=true, pipeline_output present, tools enabled) in `biozero/docs/evidence/LOG_30_uploader_cli.txt`.
- LOG_31_tls_fail.txt: mTLS negative test failure output in `biozero/docs/evidence/LOG_31_tls_fail.txt`.
- IMG_35_zeroresponder_response.txt: ZeroResponder JSON response in `biozero/docs/evidence/IMG_35_zeroresponder_response.txt`.
- LOG_34_zeroresponder_actions.log: ZeroResponder action log in `biozero/docs/evidence/LOG_34_zeroresponder_actions.log`.
- LOG_30_runner.log: Runner log capture in `biozero/docs/evidence/LOG_30_runner.log`.
- IMG_36_ui_homepage.html: UI homepage HTML snapshot in `biozero/docs/evidence/IMG_36_ui_homepage.html`.
- LOG_36_ui_health_upload.txt: UI health proxy response (502) in `biozero/docs/evidence/LOG_36_ui_health_upload.txt`.
- run_output.txt: Consolidated test run output in `biozero/docs/evidence/run_output.txt`.
- output5.txt: Latest run output showing detection verdict + signals (job_id `b2aacf0dfd25d15a`) in `biozero/infra/compose/output5.txt`.
- output01.txt: Service status + API logs confirming TLS startup and mTLS denial without client cert in `biozero/infra/compose/output01.txt`.

## Gaps
- Results authZ 403 test not captured yet (IMG_34 pending).
- Pipeline executed with tools enabled; bcftools call warning recorded in output.
- UI health proxy currently returning 502 (needs Nginx upstream TLS/mTLS adjustment).
