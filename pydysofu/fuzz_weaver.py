"""
Core fuzzing functionality.
@author twsswt
"""
import ast
import copy
import inspect
import types
import random

from core_fuzzers import identity

from workflow_transformer import WorkflowTransformer

from asp import weave_clazz, weave_module, unweave_class, unweave_all_classes, IdentityAspect

_reference_syntax_trees = dict()

def copy_func(f):
    '''
    Nicked from Aaron Hall at https://stackoverflow.com/a/30714299
    return a function with same code, globals, defaults, closure, and
    name (or provide a new name)
    '''
    fn = types.FunctionType(f.__code__, f.__globals__, f.__name__,
                            f.__defaults__, f.__closure__)
    # in case f was given attrs (note this dict is a shallow copy):
    fn.__dict__.update(f.__dict__)
    return fn


def get_reference_syntax_tree(func):
    if func not in _reference_syntax_trees:
        func_source_lines = inspect.getsourcelines(func)[0]

        global_indentation = len(func_source_lines[0]) - len(func_source_lines[0].strip())
        for i in range(len(func_source_lines)):
            func_source_lines[i] = func_source_lines[i][global_indentation - 1:]

        func_source = ''.join(func_source_lines)
        _reference_syntax_trees[func] = ast.parse(func_source)

    return _reference_syntax_trees[func]


def record_generated_syntax_tree(func, tree):
    _reference_syntax_trees[func] = tree


def fuzz_function(reference_function, fuzzer=identity, context=None):
    reference_syntax_tree = get_reference_syntax_tree(reference_function)

    fuzzed_syntax_tree = copy.deepcopy(reference_syntax_tree)
    workflow_transformer = WorkflowTransformer(fuzzer=fuzzer, context=context)
    workflow_transformer.visit(fuzzed_syntax_tree)

    # Compile the newly mutated function into a module, extract the mutated function code object and replace the
    # reference function's code object for this call.
    compiled_module = compile(fuzzed_syntax_tree, '<potentially custom>', 'exec')

    reference_function.func_code = compiled_module.co_consts[0]
    function_clone = copy_func(reference_function)
    record_generated_syntax_tree(function_clone, fuzzed_syntax_tree)
    return function_clone  # So it can be caught in the HabitFormingAspect


class FuzzingAspect(IdentityAspect):

    def __init__(self, fuzzing_advice={}):
        self.fuzzing_advice = fuzzing_advice

    def give_advice(self, fuzzing_advice):
        self.fuzzing_advice.update(fuzzing_advice)

    def prelude(self, attribute, context, *args, **kwargs):
        self.apply_fuzzing(attribute, context)

    def apply_fuzzing(self, attribute, context):
        if inspect.ismethod(attribute):
            reference_function = attribute.im_func
            # Ensure that advice key is unbound method for instance methods.
            advice_key = getattr(attribute.im_class, attribute.func_name)
        else:
            reference_function = attribute
            advice_key = reference_function

        fuzzer = self.fuzzing_advice.get(advice_key, identity)
        fuzz_function(reference_function, fuzzer, context)


class IncrementalImprover(FuzzingAspect):
    '''
    A fuzzer aspect class which improves on old variants, effectively forming habits.
    '''
    def __init__(self, variants_per_round, round_length, success_metric_function, fuzzer=lambda x: x, fuzzing_advice={}):

        super(IncrementalImprover, self).__init__(fuzzing_advice)

        self.variants_per_round = variants_per_round
        self.round_length = round_length
        self.invocation_count = 0
        self.current_attribute = None
        self.reference_attribute = None
        self.success_metric = success_metric_function
        self.advice_key_map = {}

        '''
        A list containing a dictionary for each round. Each round's dictionary is of format {variant: [results]}.
        '''
        self.variants = []

    def prelude(self, attribute, context, *args, **kwargs):
        '''

        :param attribute:
        :param context:
        :param args:
        :param kwargs:
        :return:
        '''

        if self.current_attribute is None:
            self.reference_attribute = attribute
            self.current_attribute = attribute
            self.construct_new_round(attribute, context)

        elif self.invocation_count != 0 and self.invocation_count % (self.variants_per_round * self.round_length) == 0:
            self.construct_new_round(self.best_attribute_in_current_round[0], context)

        self.invocation_count += 1

        # Select a new current variant from the round.
        self.current_attribute = None
        while self.current_attribute is None:
            # Randomly select an item from the list of format [(variant1, history1), (variant2, history2), ...]
            possible_attr = random.choice(self.current_round.items())
            if len(possible_attr[1]) != self.round_length:
                self.current_attribute = possible_attr[0]

        # reference_function.func_code = compiled_module.co_consts[0]
        if isinstance(attribute, types.MethodType):
            attribute.im_func.func_code = self.current_attribute.func_code
        else:
            attribute.func_code = self.current_attribute.func_code

    def encore(self, attribute, context, result):
        '''
        An ASP-style Encore function to record the result of a variant's execution.
        :param attribute:
        :param context:
        :param result:
        '''
        # The attribute passed in here is meaningless, because we actually care about the *variant* of the attribute
        # that was just executed. Use self.current_attribute instead.
        current_round = self.variants[-1]
        result_list = current_round[self.current_attribute]
        result_list.append(result)
        current_round[self.current_attribute] = result_list
        self.variants[-1] = current_round

    @property
    def current_round(self):
        '''
        Whatever round is currently being iterated through.
        :return: A dictionary of format {variant: [results]}.
        '''
        return self.variants[-1]

    @property
    def best_attribute_in_current_round(self):
        '''
        The attribute variant in the current round which seems to perform best
        :return: A tuple of the format (variant function, summed success metrics) which has the highest average
            of success metrics for the current round
        '''
        current_round = copy.deepcopy(self.current_round)
        for variant, results in current_round.items():
            if len(results) != 0:
                current_round[variant] = sum([self.success_metric(result) for result in results]) / len(results)
            else:
                # If something's not run yet, assume nothing.
                current_round[variant] = 0

        result_list = current_round.items()
        result_list.sort(key=lambda x: x[1])
        return result_list[-1]

    def construct_new_round(self, attribute, context):
        '''
        Constructs a new round of variants.
        :param attribute: The variant to base the next round of variants on.
        :param context: The context passed to the fuzzer
        '''
        current_round = {}

        # Iterate through a new round, and construct new variants to go in it.
        # If this is our *first* variant, add the unaltered target; sometimes original is best!
        for i in range(self.variants_per_round):
            if i == 0 and self.invocation_count == 0:
                current_round[attribute] = []

            # We're not adding the unaltered target, so generate and add a variant.
            else:
                # Ensure that advice key is unbound method for instance methods.
                if inspect.ismethod(attribute):
                    reference_function = attribute.im_func
                    advice_key = getattr(attribute.im_class, attribute.func_name)
                else:
                    reference_function, advice_key = attribute, attribute

                fuzzer = self.fuzzing_advice.get(advice_key, identity)
                variant = fuzz_function(reference_function, fuzzer, context)
                self.give_advice({variant: fuzzer})
                current_round[variant] = []

        self.variants.append(current_round)



def fuzz_clazz(clazz, fuzzing_advice, advice_aspect=FuzzingAspect()):
    '''

    :param clazz:
    :param fuzzing_advice:
    :param advice_aspect:
    :return:
    '''

    advice_aspect.give_advice(fuzzing_advice)

    advice = {k: advice_aspect for k in fuzzing_advice.keys()}

    weave_clazz(clazz, advice)


def defuzz_class(clazz):
    unweave_class(clazz)


def defuzz_all_classes():
    unweave_all_classes()


def fuzz_module(mod, advice):
    weave_module(mod, advice)
