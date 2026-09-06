from .ddos import DDoSDetector
from .recon import ReconDetector
from .c2 import C2Detector

ACTIVE_DETECTORS = [DDoSDetector, ReconDetector, C2Detector]
