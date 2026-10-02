import joblib
import numpy as np


model = joblib.load("model/intrusion_model.pkl")


def predict_attack(features):

    features = np.array(features).reshape(1,-1)

    prediction = model.predict(features)

    if prediction[0] == 0:
        return "Normal Traffic"
    else:
        return "Intrusion Detected"