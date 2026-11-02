# CloudSentinel's own detector (ADR 0011). The honeypot stack builds this from
# a folder it fills at synth (detectorImageContext): this file, the handler,
# and — unchanged — the extractor and schema the offline record uses and the
# model section 8 of docs/generalization-protocol.md chose.
FROM public.ecr.aws/lambda/python:3.12
# The versions the threshold was chosen under (ml/models/platform_detector.json):
# the handler refuses any other XGBoost. xgboost-cpu is the same library built
# without the GPU support, a twentieth of the size.
RUN pip install --no-cache-dir numpy==2.5.1 pandas==3.1.0 xgboost-cpu==3.3.0
COPY handler.py pcap_flows.py harmonize.py cross_dataset.py platform_detector.ubj ${LAMBDA_TASK_ROOT}/
CMD ["handler.handler"]
