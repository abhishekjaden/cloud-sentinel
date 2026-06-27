"""
Launch the CICIDS2017 preprocessing as a SageMaker Processing job.

Runs an SKLearnProcessor on managed infrastructure: reads raw CSVs from
the data-lake S3 bucket, executes preprocessing.py, writes train/val/test
splits back to S3. Ephemeral compute, S3 in/out — the production pattern.

NOTE: managed Processing requires the ml.m5.xlarge processing quota, which
is pending on this new account. The interim path is run_local.py (in-notebook).
"""
import sagemaker
from sagemaker.sklearn.processing import SKLearnProcessor
from sagemaker.processing import ProcessingInput, ProcessingOutput

BUCKET = "cloudsentinel-ml-743181156000"
RAW = f"s3://{BUCKET}/raw/cicids2017/"
FEATURES = f"s3://{BUCKET}/features/"

session = sagemaker.Session()
role = sagemaker.get_execution_role()
print(f"role: {role}")
print(f"region: {session.boto_region_name}")

processor = SKLearnProcessor(
    framework_version="1.2-1",
    role=role,
    instance_type="ml.m5.xlarge",
    instance_count=1,
    base_job_name="cicids-preprocess",
    sagemaker_session=session,
)

processor.run(
    code="preprocessing.py",
    inputs=[
        ProcessingInput(source=RAW, destination="/opt/ml/processing/input"),
    ],
    outputs=[
        ProcessingOutput(
            source="/opt/ml/processing/output",
            destination=FEATURES,
            output_name="splits",
        ),
    ],
    wait=True,
    logs=True,
)
print("DONE — splits written to", FEATURES)
