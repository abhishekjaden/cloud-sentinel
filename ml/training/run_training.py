"""
Launch CICIDS2017 XGBoost training as a managed SageMaker training job.

Production path: runs train.py on a managed instance, reads features from S3,
writes model artifacts to S3. Same train.py runs in-notebook as the interim
while the ml.m5.2xlarge training quota is pending on this new account.
"""
import sagemaker
from sagemaker.xgboost.estimator import XGBoost

BUCKET = "cloudsentinel-ml-743181156000"
FEATURES = f"s3://{BUCKET}/features/"
OUTPUT = f"s3://{BUCKET}/models/"

session = sagemaker.Session()
role = sagemaker.get_execution_role()
print(f"role: {role}")

estimator = XGBoost(
    entry_point="train.py",
    source_dir="ml/training",
    role=role,
    instance_type="ml.m5.2xlarge",
    instance_count=1,
    framework_version="1.7-1",
    output_path=OUTPUT,
    base_job_name="cicids-xgb",
    hyperparameters={
        "n-estimators": 300,
        "max-depth": 8,
        "learning-rate": 0.1,
    },
    sagemaker_session=session,
)

estimator.fit({"train": FEATURES}, wait=True, logs=True)
print("DONE — model artifacts in", OUTPUT)
