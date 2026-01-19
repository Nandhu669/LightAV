import onnxruntime as ort
import numpy as np

class StaticONNXModel:
    def __init__(self, model_path):
        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"]
        )
        self.input_name = self.session.get_inputs()[0].name
        self.feature_count = self.session.get_inputs()[0].shape[1]

    def predict(self, features):
        """
        features: numpy array of shape (N, feature_count)
        returns: predicted labels (0 or 1)
        """
        if features.shape[1] != self.feature_count:
            raise ValueError("Feature size mismatch")

        outputs = self.session.run(
            None,
            {self.input_name: features.astype(np.float32)}
        )

        # LightGBM ONNX outputs class labels directly
        return outputs[0]
