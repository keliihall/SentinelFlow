# Example Invalid Parser

Safe fixture plugin for P5.5 consistency tests.

The runner only echoes local JSON input. The manifest intentionally selects the
trusted `fixture-invalid-output-v1` built-in parser, which returns an invalid
normalization envelope. This exercises parser/normalizer failure handling without
performing scanning, exploitation, probing, or network activity.

