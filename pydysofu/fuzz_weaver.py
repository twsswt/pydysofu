"""
Core fuzzing functionality.
@author twsswt
"""
import ast
import copy
import inspect

from core_fuzzers import identity

from inspect import getmembers

from workflow_transformer import WorkflowTransformer


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


def fuzz_function(reference_function, fuzzer=identity):
    reference_syntax_tree = get_reference_syntax_tree(reference_function)

    fuzzed_syntax_tree = copy.deepcopy(reference_syntax_tree)
    workflow_transformer = WorkflowTransformer(fuzzer)
    workflow_transformer.visit(fuzzed_syntax_tree)

    # Compile the newly mutated function into a module, extract the mutated function code object and replace the
    # reference function's code object for this call.
    compiled_module = compile(fuzzed_syntax_tree, inspect.getsourcefile(reference_function), 'exec')
    reference_function.func_code = compiled_module.co_consts[0]


def fuzz_clazz(clazz, advice):

    """
    Applies fuzzers specified in the supplied advice dictionary to methods in supplied class.
    :param clazz : the class to fuzz.
    :param advice : the dictionary of method->fuzzer mappings to apply.  If no fuzzer is specified for a function then
    the identity fuzzer is applied in case the method has been previously fuzzed.
    """
    def __fuzzed_getattribute__(self, item):
        attribute = object.__getattribute__(self, item)

        if item[0:2] == '__':
            return attribute

        elif inspect.ismethod(attribute):

            def wrap(*args, **kwargs):

                reference_method = attribute.im_func
                # Ensure that advice key is unbound method for instance methods.
                advice_key = getattr(attribute.im_class, attribute.func_name)
                fuzzer = advice.get(advice_key, identity)
                fuzz_function(reference_method, fuzzer)

                # Execute the mutated method.
                return reference_method(self, *args, **kwargs)
            wrap.func_name = attribute.func_name
            return wrap

        elif inspect.isfunction(attribute):

            def wrap(*args, **kwargs):

                reference_function = attribute
                fuzzer = advice.get(reference_function, identity)
                fuzz_function(reference_function, fuzzer)

                # Execute the mutated function.
                return reference_function(*args, **kwargs)

            return wrap
        else:
            return attribute

    clazz.__getattribute__ = __fuzzed_getattribute__


def fuzz_module(mod, advice):
    """
    Applies fuzzers specified in the supplied advice dictionary to methods in supplied module.  All member classes and
    functions are inspected in turn, with the specified advice being applied to each.
    :param mod : the module to fuzz.
    :param advice : the dictionary of method->fuzzer mappings to apply.
    """
    for _, member in getmembers(mod):
        if inspect.isclass(member):
            fuzz_clazz(member, advice)
