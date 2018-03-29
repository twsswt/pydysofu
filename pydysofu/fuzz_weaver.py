"""
Core fuzzing functionality.
@author twsswt
"""
import ast
import copy
import inspect

from core_fuzzers import identity

from workflow_transformer import WorkflowTransformer

from asp import weave_clazz, weave_module, unweave_class, unweave_all_classes, IdentityAspect

_reference_syntax_trees = dict()


def get_reference_syntax_tree(func):
    if func not in _reference_syntax_trees:
        func_source_lines = inspect.getsourcelines(func)[0]

        global_indentation = len(func_source_lines[0]) - len(func_source_lines[0].strip())
        for i in range(len(func_source_lines)):
            func_source_lines[i] = func_source_lines[i][global_indentation - 1:]

        func_source = ''.join(func_source_lines)
        _reference_syntax_trees[func] = ast.parse(func_source)

    return _reference_syntax_trees[func]


def fuzz_function(reference_function, fuzzer=identity, context=None):
    reference_syntax_tree = get_reference_syntax_tree(reference_function)

    fuzzed_syntax_tree = copy.deepcopy(reference_syntax_tree)
    workflow_transformer = WorkflowTransformer(fuzzer=fuzzer, context=context)
    workflow_transformer.visit(fuzzed_syntax_tree)

    # Compile the newly mutated function into a module, extract the mutated function code object and replace the
    # reference function's code object for this call.
    compiled_module = compile(fuzzed_syntax_tree, inspect.getsourcefile(reference_function), 'exec')

    reference_function.func_code = compiled_module.co_consts[0]


class FuzzingAspect(IdentityAspect):

    def __init__(self, fuzzing_advice):
        self.fuzzing_advice = fuzzing_advice

    def prelude(self, attribute, context, *args, **kwargs):
        self.apply_fuzzing(attribute, context)

    def apply_fuzzing(self, attribute, context):
        # Ensure that advice key is unbound method for instance methods.
        if inspect.ismethod(attribute):
            reference_function = attribute.im_func
            advice_key = getattr(attribute.im_class, attribute.func_name)
        else:
            reference_function = attribute
            advice_key = reference_function

        fuzzer = self.fuzzing_advice.get(advice_key, identity)
        fuzz_function(reference_function, fuzzer, context)


def fuzz_clazz(clazz, fuzzing_advice):

    fuzzing_aspect = FuzzingAspect(fuzzing_advice)

    advice = {k: fuzzing_aspect for k in fuzzing_advice.keys()}

    weave_clazz(clazz, advice)


def defuzz_class(clazz):
    unweave_class(clazz)


def defuzz_all_classes():
    unweave_all_classes()


def fuzz_module(mod, advice):
    weave_module(mod, advice)
