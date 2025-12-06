"""
ML Detection Engine
Loads the trained model and performs real-time inference on extracted features
"""

import os
import torch
import numpy as np
import logging
from typing import Tuple, Dict
from sklearn.preprocessing import StandardScaler
import pickle

# Import CNN+Attention model
from cnn_attention_model import CNNAttentionModel

class DetectionEngine:
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Model configuration
        self.model_path = config['model']['path']
        self.confidence_threshold = config['model']['confidence_threshold']
        self.class_names = config['model']['classes']

        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.logger.info(f"Using device: {self.device}")

        # Load model
        self.model = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        """Load the trained model and scaler"""
        try:
            self.logger.info(f"Loading model from {self.model_path}")

            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model not found: {self.model_path}")

            # Load checkpoint
            checkpoint = torch.load(self.model_path, map_location=self.device, weights_only=False)

            # Extract model parameters
            input_dim = checkpoint.get('input_dim', 83)
            num_classes = len(self.class_names)

            # Initialize model
            self.model = CNNAttentionModel(
                input_dim=input_dim,
                num_classes=num_classes,
                dropout=0.5
            ).to(self.device)

            # Load weights
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()

            # Load scaler
            self.scaler = checkpoint.get('scaler', None)
            if self.scaler is None:
                self.logger.warning("No scaler found in checkpoint, creating new one")
                self.scaler = StandardScaler()

            self.logger.info(f"✓ Model loaded successfully")
            self.logger.info(f"  Input features: {input_dim}")
            self.logger.info(f"  Output classes: {num_classes}")
            self.logger.info(f"  Classes: {list(self.class_names.values())}")

            if 'production_score' in checkpoint:
                self.logger.info(f"  Production score: {checkpoint['production_score']*100:.2f}%")

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise

    def predict(self, features: np.ndarray) -> Tuple[str, float, Dict]:
        """
        Predict malware class for given features

        Args:
            features: numpy array of 83 features

        Returns:
            (predicted_class, confidence, probabilities_dict)
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")

        try:
            # Validate input
            if features.shape[0] != 83:
                raise ValueError(f"Expected 83 features, got {features.shape[0]}")

            # Normalize features
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            # Convert to tensor
            features_tensor = torch.FloatTensor(features_scaled).to(self.device)

            # Inference
            with torch.no_grad():
                outputs = self.model(features_tensor)
                probabilities = torch.softmax(outputs, dim=1)

                # Get prediction
                confidence, predicted_class_idx = torch.max(probabilities, 1)

                confidence = confidence.item()
                predicted_class_idx = predicted_class_idx.item()

            # Get class name
            predicted_class = self.class_names[predicted_class_idx]

            # Get all probabilities
            prob_dict = {
                self.class_names[i]: probabilities[0][i].item()
                for i in range(len(self.class_names))
            }

            self.logger.info(
                f"Prediction: {predicted_class} ({confidence*100:.2f}% confidence)"
            )

            return predicted_class, confidence, prob_dict

        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            raise

    def is_malware(self, features: np.ndarray) -> Tuple[bool, str, float, Dict]:
        """
        Determine if features indicate malware

        Returns:
            (is_malware, class_name, confidence, probabilities)
        """
        predicted_class, confidence, probabilities = self.predict(features)

        # Check if confidence meets threshold
        if confidence < self.confidence_threshold:
            self.logger.info(
                f"Low confidence ({confidence*100:.1f}%) - treating as uncertain"
            )
            return False, predicted_class, confidence, probabilities

        # ONLY detect RANSOMWARE (ignore Spyware, Trojan, etc.)
        # This is a ransomware-specific detector
        is_malware = predicted_class == "Ransomware"

        if is_malware:
            self.logger.warning(
                f"🚨 RANSOMWARE DETECTED: {predicted_class} ({confidence*100:.1f}%)"
            )
        elif predicted_class != "Benign":
            self.logger.info(
                f"ℹ️ Other malware detected ({predicted_class}) - ignoring (ransomware detector only)"
            )
        else:
            self.logger.info(
                f"✓ Benign process ({confidence*100:.1f}%)"
            )

        return is_malware, predicted_class, confidence, probabilities

    def get_threat_priority(self, malware_class: str) -> int:
        """
        Get priority level for threat response
        Higher number = higher priority

        Returns:
            1-3 priority level
        """
        priority_map = {
            "Ransomware": 3,  # Highest - encrypts files immediately
            "Trojan": 2,      # Medium - can cause damage
            "Spyware": 2,     # Medium - steals data
            "Benign": 0       # No action needed
        }

        return priority_map.get(malware_class, 0)

    def generate_detection_report(self, features: np.ndarray, process_info: Dict) -> Dict:
        """
        Generate detailed detection report

        Returns:
            Dictionary with detection details
        """
        predicted_class, confidence, probabilities = self.predict(features)
        is_malware = predicted_class != "Benign" and confidence >= self.confidence_threshold

        report = {
            'process': {
                'pid': process_info.get('pid'),
                'name': process_info.get('name'),
                'executable': process_info.get('exe'),
                'timestamp': process_info.get('timestamp')
            },
            'detection': {
                'is_malware': is_malware,
                'predicted_class': predicted_class,
                'confidence': confidence,
                'meets_threshold': confidence >= self.confidence_threshold,
                'threshold': self.confidence_threshold
            },
            'probabilities': probabilities,
            'threat_level': self.get_threat_priority(predicted_class),
            'recommended_action': 'KILL' if is_malware else 'MONITOR'
        }

        return report


if __name__ == "__main__":
    # Test detection engine
    import yaml

    logging.basicConfig(level=logging.INFO)

    with open('../config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    # Initialize engine
    try:
        engine = DetectionEngine(config)
        print("\n✓ Detection engine initialized")

        # Test with random features (simulation)
        test_features = np.random.rand(83)

        print("\nTesting prediction...")
        predicted_class, confidence, probs = engine.predict(test_features)

        print(f"\nPrediction Results:")
        print(f"  Class: {predicted_class}")
        print(f"  Confidence: {confidence*100:.2f}%")
        print(f"\nAll probabilities:")
        for class_name, prob in probs.items():
            print(f"  {class_name}: {prob*100:.2f}%")

        # Test malware detection
        is_malware, class_name, conf, _ = engine.is_malware(test_features)
        print(f"\nMalware Detection:")
        print(f"  Is Malware: {is_malware}")
        print(f"  Class: {class_name}")
        print(f"  Confidence: {conf*100:.2f}%")

    except Exception as e:
        print(f"\n✗ Error: {e}")
