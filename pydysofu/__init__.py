"""
Front end API for the fuzzi_moss library.
"""

from .fuzz_decorator import fuzz
from .fuzz_weaver import fuzz_clazz, defuzz_class, fuzz_module, defuzz_all_classes
from .config import pydysofu_random
from .core_fuzzers import fuzzer_invocations, fuzzer_invocations_count, reset_invocation_counters
