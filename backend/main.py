import os
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib

# Paths to ML artifacts and dataset
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_DIR = os.path.join(BASE_DIR, "ml")
MODEL_PATH = os.path.join(ML_DIR, "model.joblib")
FEATURES_PATH = os.path.join(ML_DIR, "features.joblib")
DATA_PATH = os.path.join(ML_DIR, "data", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

# Global variables for model and feature list
model = None
features = []

# Step 1: Lifespan handler to load model and features on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, features
    print("Loading ML model and features list...")
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        raise RuntimeError("Model or features file missing. Run ml/train.py first.")
    model = joblib.load(MODEL_PATH)
    features = joblib.load(FEATURES_PATH)
    print(f"Model and {len(features)} feature columns loaded successfully.")
    yield

# Initialize FastAPI application
app = FastAPI(title="Campus Network Threat Detection API", lifespan=lifespan)

# Step 5: Enable CORS for React frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper: Generate Cisco ACL block command for detected threat
def generate_cisco_acl(ip: str) -> str:
    return (
        f"ip access-list extended BLOCK_ATTACKER\n"
        f" deny ip host {ip} any\n"
        f" permit ip any any\n"
        f"interface GigabitEthernet0/1\n"
        f" ip access-group BLOCK_ATTACKER in"
    )

# Response schema for predictions
class PredictionResult(BaseModel):
    source_ip: str
    prediction: str
    confidence: float
    severity: str
    cisco_acl: Optional[str] = None

# Step 2: GET /sample endpoint
# Returns 5 normal flows and 5 port scan flows with fake source IPs (without Label)
@app.get("/sample", response_model=List[Dict[str, Any]])
def get_sample():
    if not os.path.exists(DATA_PATH):
        raise HTTPException(status_code=404, detail="Dataset CSV file not found.")

    benign_rows = []
    scan_rows = []

    # Read CSV in chunks to quickly find 5 benign and 5 scan flows without reading full 76MB
    for chunk in pd.read_csv(DATA_PATH, chunksize=10000):
        chunk.columns = chunk.columns.str.strip()
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)
        chunk["Label"] = chunk["Label"].astype(str).str.strip()

        if len(benign_rows) < 5:
            needed = 5 - len(benign_rows)
            benign_rows.extend(chunk[chunk["Label"] == "BENIGN"].head(needed).to_dict(orient="records"))

        if len(scan_rows) < 5:
            needed = 5 - len(scan_rows)
            scan_rows.extend(chunk[chunk["Label"] == "PortScan"].head(needed).to_dict(orient="records"))

        if len(benign_rows) >= 5 and len(scan_rows) >= 5:
            break

    sampled_flows = []

    # Normal flows: assign individual 192.168.10.x IPs
    for i, row in enumerate(benign_rows):
        row.pop("Label", None)
        row["source_ip"] = f"192.168.10.{14 + i}"
        sampled_flows.append(row)

    # PortScan attack flows: assign attacker IP 192.168.10.45
    for row in scan_rows:
        row.pop("Label", None)
        row["source_ip"] = "192.168.10.45"
        sampled_flows.append(row)

    return sampled_flows

# Step 3 & 4: POST /predict endpoint
# Receives a list of flows (features + source_ip) and returns threat analysis and ACL commands
@app.post("/predict", response_model=List[PredictionResult])
def predict(flows: List[Dict[str, Any]]):
    if model is None or not features:
        raise HTTPException(status_code=500, detail="Model is not loaded.")
    if not flows:
        return []

    # Extract source IPs and feature table
    source_ips = [flow.get("source_ip", "Unknown") for flow in flows]
    df_input = pd.DataFrame(flows)

    # Ensure all required features exist and match expected training columns
    X = df_input.reindex(columns=features, fill_value=0.0).astype(float)
    X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # Run predictions and confidence estimation
    raw_preds = model.predict(X)
    probs = model.predict_proba(X)

    results = []
    for i in range(len(flows)):
        ip = source_ips[i]
        pred_label = "PortScan" if raw_preds[i] == 1 else "BENIGN"
        prob_score = float(probs[i][raw_preds[i]])
        confidence = round(prob_score, 4)

        if pred_label == "PortScan":
            severity = "High" if confidence >= 0.80 else "Medium"
            cisco_acl = generate_cisco_acl(ip)
        else:
            severity = "Low"
            cisco_acl = None

        results.append(
            PredictionResult(
                source_ip=ip,
                prediction=pred_label,
                confidence=confidence,
                severity=severity,
                cisco_acl=cisco_acl,
            )
        )

    return results
