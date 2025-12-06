"""
Real-time Ransomware Detection Agent using ONNX Runtime.

This script provides:
- PyTorch model to ONNX export functionality
- Real-time inference using ONNX Runtime (cross-platform: Mac MPS/CPU, Windows)
- Lightweight deployment-ready detection agent
- <50ms inference time per sample

Compatible with both Mac (testing) and Windows (production VM deployment).
"""

import torch
import numpy as np
import onnxruntime as ort
import time
import pickle
from typing import Tuple, List, Optional
import os


class ONNXExporter:
    """Export PyTorch model to ONNX format."""

    @staticmethod
    def export_model(model: torch.nn.Module, input_dim: int, sequence_length: int = 1,
                    output_path: str = '../models/ransomware_detector.onnx',
                    opset_version: int = 16):
        """
        Export PyTorch model to ONNX format.

        Args:
            model: Trained PyTorch model
            input_dim: Input feature dimension
            sequence_length: Sequence length for BiLSTM
            output_path: Path to save ONNX model
            opset_version: ONNX opset version (16+ recommended)
        """
        model.eval()

        # Create dummy input
        dummy_input = torch.randn(1, sequence_length, input_dim)

        # Export to ONNX
        print(f"Exporting model to ONNX format...")
        print(f"  Input shape: {list(dummy_input.shape)}")
        print(f"  Opset version: {opset_version}")

        torch.onnx.export(
            model,
            dummy_input,
            output_path,
            export_params=True,
            opset_version=opset_version,
            do_constant_folding=True,
            input_names=['input'],
            output_names=['output'],
            dynamic_axes={
                'input': {0: 'batch_size'},
                'output': {0: 'batch_size'}
            }
        )

        # Verify export
        import onnx
        onnx_model = onnx.load(output_path)
        onnx.checker.check_model(onnx_model)

        file_size = os.path.getsize(output_path) / (1024 * 1024)  # MB
        print(f"\n✓ Model exported successfully!")
        print(f"  Saved to: {output_path}")
        print(f"  File size: {file_size:.2f} MB")

        return output_path


class RansomwareDetectionAgent:
    """
    Real-time ransomware detection agent using ONNX Runtime.

    This agent provides fast, cross-platform inference for ransomware detection.
    Compatible with Mac (MPS/CPU) and Windows.
    """

    def __init__(self, model_path: str, preprocessor_path: str, device: str = 'cpu'):
        """
        Initialize detection agent.

        Args:
            model_path: Path to ONNX model file
            preprocessor_path: Path to preprocessor pickle file
            device: Device for inference ('cpu' recommended for ONNX)
        """
        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        self.device = device

        # Load preprocessor
        self._load_preprocessor()

        # Initialize ONNX Runtime session
        self._init_onnx_session()

        print(f"\n✓ Ransomware Detection Agent initialized")
        print(f"  Model: {model_path}")
        print(f"  Device: {device}")
        print(f"  Classes: {self.class_names}")

    def _load_preprocessor(self):
        """Load scaler and label encoder."""
        with open(self.preprocessor_path, 'rb') as f:
            preprocessor = pickle.load(f)

        self.scaler = preprocessor['scaler']
        self.label_encoder = preprocessor['label_encoder']
        self.feature_cols = preprocessor['feature_cols']
        self.class_names = preprocessor['class_names']

        print(f"✓ Preprocessor loaded: {len(self.feature_cols)} features")

    def _init_onnx_session(self):
        """Initialize ONNX Runtime inference session."""
        # Session options for optimization
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        # Choose execution provider based on platform
        providers = ['CPUExecutionProvider']  # Works on all platforms

        # Create session
        self.session = ort.InferenceSession(
            self.model_path,
            sess_options=sess_options,
            providers=providers
        )

        # Get input/output names
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name

        print(f"✓ ONNX Runtime session created")
        print(f"  Providers: {providers}")

    def preprocess(self, features: np.ndarray) -> np.ndarray:
        """
        Preprocess input features.

        Args:
            features: Raw feature array (n_samples, n_features) or (n_features,)

        Returns:
            Preprocessed features ready for inference
        """
        # Handle single sample
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        # Validate feature dimension
        if features.shape[1] != len(self.feature_cols):
            raise ValueError(
                f"Expected {len(self.feature_cols)} features, got {features.shape[1]}"
            )

        # Normalize using scaler
        features_scaled = self.scaler.transform(features)

        # Reshape for ONNX model: (batch_size, seq_len, n_features)
        features_reshaped = features_scaled.reshape(features_scaled.shape[0], 1, -1)

        return features_reshaped.astype(np.float32)

    def predict(self, features: np.ndarray) -> Tuple[List[str], np.ndarray, float]:
        """
        Predict ransomware class for input features.

        Args:
            features: Raw feature array (n_samples, n_features) or (n_features,)

        Returns:
            (predicted_classes, probabilities, inference_time_ms) tuple
        """
        # Preprocess
        features_processed = self.preprocess(features)

        # Inference
        start_time = time.time()
        outputs = self.session.run(
            [self.output_name],
            {self.input_name: features_processed}
        )[0]
        inference_time = (time.time() - start_time) * 1000  # ms

        # Get predictions
        probabilities = self._softmax(outputs)
        predicted_indices = np.argmax(outputs, axis=1)
        predicted_classes = [self.class_names[idx] for idx in predicted_indices]

        return predicted_classes, probabilities, inference_time

    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        """Compute softmax probabilities."""
        exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=1, keepdims=True)

    def predict_single(self, features: np.ndarray, verbose: bool = True) -> dict:
        """
        Predict for a single sample with detailed output.

        Args:
            features: Feature array (n_features,)
            verbose: Print detection result

        Returns:
            Dictionary with prediction details
        """
        predictions, probabilities, inference_time = self.predict(features)

        result = {
            'class': predictions[0],
            'confidence': float(np.max(probabilities[0])) * 100,
            'probabilities': {
                cls: float(prob) * 100
                for cls, prob in zip(self.class_names, probabilities[0])
            },
            'inference_time_ms': inference_time,
            'is_malware': predictions[0] != 'Benign'
        }

        if verbose:
            self._print_detection(result)

        return result

    def _print_detection(self, result: dict):
        """Print detection result in a formatted way."""
        print("\n" + "="*70)
        print("RANSOMWARE DETECTION RESULT")
        print("="*70)
        print(f"Detected Class: {result['class']}")
        print(f"Confidence:     {result['confidence']:.2f}%")
        print(f"Malware:        {'YES ⚠️' if result['is_malware'] else 'NO ✓'}")
        print(f"\nClass Probabilities:")
        for cls, prob in result['probabilities'].items():
            bar_length = int(prob / 2)  # Scale to 50 chars max
            bar = '█' * bar_length
            print(f"  {cls:15s}: {prob:6.2f}% {bar}")
        print(f"\nInference Time: {result['inference_time_ms']:.2f} ms")
        print("="*70)

    def benchmark(self, num_samples: int = 1000) -> dict:
        """
        Benchmark inference performance.

        Args:
            num_samples: Number of samples to test

        Returns:
            Dictionary with performance statistics
        """
        print(f"\nBenchmarking with {num_samples} samples...")

        # Generate random features for testing
        features = np.random.randn(num_samples, len(self.feature_cols)).astype(np.float32)

        # Warm-up
        _ = self.predict(features[:10])

        # Benchmark
        times = []
        batch_size = 32

        for i in range(0, num_samples, batch_size):
            batch = features[i:i+batch_size]
            _, _, inference_time = self.predict(batch)
            times.append(inference_time / len(batch))  # Per-sample time

        stats = {
            'mean_ms': np.mean(times),
            'std_ms': np.std(times),
            'min_ms': np.min(times),
            'max_ms': np.max(times),
            'median_ms': np.median(times),
            'p95_ms': np.percentile(times, 95),
            'p99_ms': np.percentile(times, 99)
        }

        # Print results
        print("\n" + "="*70)
        print("BENCHMARK RESULTS")
        print("="*70)
        print(f"Samples tested:  {num_samples}")
        print(f"Mean time:       {stats['mean_ms']:.3f} ms per sample")
        print(f"Std deviation:   {stats['std_ms']:.3f} ms")
        print(f"Min time:        {stats['min_ms']:.3f} ms")
        print(f"Max time:        {stats['max_ms']:.3f} ms")
        print(f"Median time:     {stats['median_ms']:.3f} ms")
        print(f"95th percentile: {stats['p95_ms']:.3f} ms")
        print(f"99th percentile: {stats['p99_ms']:.3f} ms")
        print("\n" + ("✓ Target <50ms: PASS" if stats['p95_ms'] < 50 else "⚠ Target <50ms: FAIL"))
        print("="*70)

        return stats


# Example usage and testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Ransomware Detection Agent')
    parser.add_argument('--mode', type=str, default='test',
                       choices=['export', 'test', 'benchmark'],
                       help='Operation mode')
    parser.add_argument('--model', type=str, default='../models/best_ransomware_detector.onnx',
                       help='Path to ONNX model')
    parser.add_argument('--preprocessor', type=str, default='../models/preprocessor.pkl',
                       help='Path to preprocessor')
    args = parser.parse_args()

    if args.mode == 'export':
        # Export PyTorch model to ONNX
        print("="*70)
        print("EXPORTING PYTORCH MODEL TO ONNX")
        print("="*70)

        # This requires a trained PyTorch model
        from model import GNBiLSTMAttention
        import torch

        # Load trained model (you need to train it first!)
        model = GNBiLSTMAttention(
            input_dim=55,  # CIC-MalMem features
            hidden_dim=128,
            num_layers=2,
            num_heads=4,
            num_classes=4
        )

        # Load weights (example - adjust path as needed)
        checkpoint_path = '../models/GN_BiLSTM_Attention_Full_best.pth'
        if os.path.exists(checkpoint_path):
            checkpoint = torch.load(checkpoint_path, map_location='cpu')
            model.load_state_dict(checkpoint['model_state_dict'])
            print(f"✓ Loaded model weights from {checkpoint_path}")
        else:
            print(f"⚠ No checkpoint found at {checkpoint_path}, using random weights")

        # Export
        ONNXExporter.export_model(
            model=model,
            input_dim=55,
            sequence_length=1,
            output_path=args.model
        )

    elif args.mode == 'test':
        # Test real-time detection
        print("="*70)
        print("TESTING REAL-TIME RANSOMWARE DETECTION")
        print("="*70)

        # Initialize agent
        agent = RansomwareDetectionAgent(
            model_path=args.model,
            preprocessor_path=args.preprocessor
        )

        # Test with random features (in real use, these would be actual memory features)
        print("\nTesting with simulated memory features...")
        for i in range(3):
            test_features = np.random.randn(55)  # Random features for demo
            result = agent.predict_single(test_features, verbose=True)
            time.sleep(0.5)

    elif args.mode == 'benchmark':
        # Benchmark performance
        print("="*70)
        print("BENCHMARKING INFERENCE PERFORMANCE")
        print("="*70)

        agent = RansomwareDetectionAgent(
            model_path=args.model,
            preprocessor_path=args.preprocessor
        )

        stats = agent.benchmark(num_samples=1000)

    print("\n✓ Agent operations complete!")
