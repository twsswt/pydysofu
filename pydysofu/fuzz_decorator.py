"""
@author probablytom
@author twsswt
"""

from core_fuzzers import identity

from fuzz_weaver import fuzz_function


# noinspection PyPep8Naming
class fuzz(object):
    """
    A general purpose decorator for applying fuzzings to functions containing workflow steps.

    Attributes:
    enable_fuzzings is by default set to False, but can be set to false to globally disable fuzzing.
    """

    enable_fuzzings = False

    def __init__(self, fuzzer=identity):
        self.fuzzer = fuzzer
        self._original_syntax_tree = None

    def __call__(self, func):

        def wrap(*args, **kwargs):

            if not fuzz.enable_fuzzings:
                return func(*args, **kwargs)

            fuzz_function(func, self.fuzzer)

            # Execute the mutated function.
            return func(*args, **kwargs)

        return wrap
