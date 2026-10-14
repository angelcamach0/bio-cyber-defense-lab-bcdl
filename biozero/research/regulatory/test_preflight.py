"""Offline evidence gates: unavailable dependencies must never become a pass."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("preflight", Path(__file__).with_name("preflight.py"))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def metadata(self, version=(3, 11, 0)):
        return {"python_version_info": list(version), "architecture": "aarch64"}

    def test_python39_never_imports_torch_and_stays_pending(self):
        loader = Mock(side_effect=AssertionError("must not import"))
        report = preflight.build_report(self.metadata((3, 9, 25)), loader)
        loader.assert_not_called()
        self.assertEqual(report["synthetic_probe"]["status"], "pending")
        self.assertEqual(report["checkpoint_compatibility"], "pending")

    def test_missing_torch_is_not_pass(self):
        loader = Mock(side_effect=ModuleNotFoundError("No module named 'torch'"))
        report = preflight.build_report(self.metadata(), loader)
        self.assertEqual(report["synthetic_probe"]["status"], "pending")
        self.assertFalse(report["trained_weights_loaded"])
        self.assertFalse(report["network_access_performed"])

    def fake_torch(self, engines):
        torch = Mock()
        torch.__version__ = "test-double"
        torch.backends.quantized.supported_engines = engines
        torch.backends.quantized.engine = 'fbgemm'
        torch.ao.quantization.get_default_qconfig.return_value = "test-qconfig"
        return torch

    def test_unsupported_engine_does_not_run_synthetic_model(self):
        torch = self.fake_torch(["qnnpack", "none"])
        with patch.object(preflight, "synthetic_probe") as probe:
            report = preflight.build_report(self.metadata(), lambda: torch)
        probe.assert_not_called()
        self.assertEqual(report["synthetic_probe"]["status"], "pending")
        self.assertEqual(report["supported_quantized_engines"], ["qnnpack", "none"])

    def test_execution_failure_is_not_pending_or_pass(self):
        torch = self.fake_torch(["fbgemm"])
        with patch.object(preflight, "synthetic_probe", side_effect=RuntimeError("unsupported op")):
            report = preflight.build_report(self.metadata(), lambda: torch)
        self.assertEqual(report["synthetic_probe"]["status"], "failed")
        self.assertIn("unsupported op", report["synthetic_probe"]["diagnostic"])

    def test_synthetic_success_never_claims_checkpoint_compatibility(self):
        torch = self.fake_torch(["fbgemm"])
        with patch.object(preflight, "synthetic_probe", return_value={"status": "passed"}):
            report = preflight.build_report(self.metadata(), lambda: torch)
        self.assertEqual(report["synthetic_probe"]["status"], "passed")
        self.assertEqual(report["checkpoint_compatibility"], "pending")
        self.assertEqual(report["scientific_feasibility"], "pending")

    def test_sei_qconfig_does_not_force_the_same_execution_engine(self):
        torch = self.fake_torch(['qnnpack'])
        torch.backends.quantized.engine = 'qnnpack'
        with patch.object(preflight, 'synthetic_probe', return_value={'status': 'passed'}) as probe:
            report = preflight.build_report(self.metadata(), lambda: torch)
        torch.ao.quantization.get_default_qconfig.assert_called_once_with('fbgemm')
        probe.assert_called_once_with(torch, 'qnnpack', 'fbgemm')
        self.assertEqual(report['requested_engine'], 'current')
        self.assertEqual(report['effective_quantized_engine'], 'qnnpack')


if __name__ == "__main__":
    unittest.main()
