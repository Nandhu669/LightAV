import joblib
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

# 1. Load the fully trained model (864 benign/malware samples)
path = 'lightgbm_static_balanced.pkl'
print("Loading balanced model...")
model = joblib.load(path)

# 3. Save as a standard Text Model (The most reliable format)
model.booster_.save_model('production/ai_engine/models/final_brain.txt')
print("SUCCESS: Created final_brain.txt")

# 4. Optional: Create the ONNX version
initial_type = [('float_input', FloatTensorType([None, 11]))]
onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type)
with open("production/ai_engine/models/lightgbm_static.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
print("SUCCESS: Created lightgbm_static.onnx")
