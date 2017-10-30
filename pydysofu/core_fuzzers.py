"""
Provides a library of standard fuzz operators for work flows that can be assembled into domain specific fuzz operators.

All fuzz operators are of the form fuzzer(steps, context). Steps is the sequence of steps of a method or function
that may be altered by the fuzzer. The context is the method's bound object, or None if an unbound function is fuzzed.

@author probablytom
@author twsswt
"""


import ast
import _ast
from ast import If, While

from threading import Lock

import copy

import inspect

from .find_lambda import find_lambda_ast
from .config import pydysofu_random


# Logging Machinery

_fuzzer_invocations_lock = Lock()
fuzzer_invocations = dict()


def fuzzer_invocations_count(workflow=None):

    filtered_values = \
        filter(lambda t: t[0][0] == workflow, fuzzer_invocations.items()) if workflow is not None \
        else fuzzer_invocations.items()

    return sum(map(lambda t: t[1], filtered_values))


def reset_invocation_counters():
    global fuzzer_invocations
    fuzzer_invocations = dict()


def log_invocation(func):
    def func_wrapper(*args, **kwargs):
        _fuzzer_invocations_lock.acquire()
        key = (args[1].__class__, func)
        fuzzer_invocations[key] = fuzzer_invocations.get(key, 0) + 1
        _fuzzer_invocations_lock.release()
        return func(*args, **kwargs)
    return func_wrapper


# Identity Fuzzer

def identity(steps, context):
    """
    The identity fuzzer, which returns the provided steps.
    """
    return steps


# Step Filtering Functions

def choose_identity(steps):
    return [(0, len(steps))]


def choose_random_steps(n):

    def _choose_random_steps(steps):
        if len(steps) <= n:
            return [(0, len(steps)-1)]
        else:
            sample_indices = pydysofu_random.sample(range(0, len(steps) - 1), n)
            return [(i, i+1) for i in sample_indices]

    return _choose_random_steps


def choose_last_steps(n, reapply=True):

    class _choose_last_steps(object):

        def __init__(self, _n, _reapply):
            self.n = _n
            self.reapply = _reapply

        def __call__(self, steps):

            selected = list()

            total_size = 0

            end_index = len(steps) - 1
            begin_index = end_index

            def chunk_size():
                return end_index - begin_index + 1

            def current_step_is_pass():
                return type(steps[begin_index]) is ast.Pass

            while total_size < self.n and begin_index >= 0:
                while (chunk_size() + total_size < self.n or current_step_is_pass()) and begin_index > 0:
                    begin_index -= 1

                selected.append((begin_index, end_index + 1))
                total_size += chunk_size()

                end_index = begin_index - 1
                begin_index = end_index

            if not self.reapply:
                self.n -= total_size
            return selected

    return _choose_last_steps(n, reapply)


def choose_last_step(steps):
    func = choose_last_steps(1)
    return func(steps)


_ast_control_structure_types = {ast.For, ast.If, ast.TryExcept, ast.While, ast.Return, ast.FunctionDef}


def exclude_control_structures(target=_ast_control_structure_types):

    def _exclude_control_structures(steps):
        result = list()
        start = 0
        while start < len(steps) and type(steps[start]) in _ast_control_structure_types & target:
            start += 1
        end = start
        while end < len(steps):
            while end < len(steps) and type(steps[end]) not in _ast_control_structure_types & target:
                end += 1
            result.append((start, end))
            start = end
            end = start + 1

        return result

    return _exclude_control_structures


def include_control_structures(target=_ast_control_structure_types):
    def _include_control_structures(steps):
        result = list()
        start = 0
        while start < len(steps) and type(steps[start]) not in _ast_control_structure_types & target:
            start += 1
        end = start
        while end < len(steps):
            while end < len(steps) and type(steps[end]) in _ast_control_structure_types & target:
                end += 1
            result.append((start, end))
            start = end
            end = start + 1
        return result

    return _include_control_structures


def invert(fuzz_filter):
    """
    Inverts the application of the supplied filter.  Note that invert is symmetrical, i.e.
    invert(invert(f)) is f.
    """
    def _invert(steps):
        original = fuzz_filter(steps)
        inverted = list()

        start = 0
        for block in original:
            end = block[0]
            inverted.append((start, end))
            start = block[1]

        if not start == len(steps):
            inverted.append((start, len(steps)))
        if inverted[0] == (0, 0):
            inverted.pop(0)

        return inverted

    return _invert


# Composite Fuzzers

def filter_context(fuzz_filters=[(lambda context: True, identity)]):
    """
    A composite fuzzer that accepts a sequence of context filter, fuzz operator tuples.  Each context filter must be a
    function that accepts a context and return a boolean value if the filter is satisfied by the context.  The
    associated fuzz operator is applied when the context filter returns True.
    """
    def _filter_context(steps, context):

        for fuzz_filter, fuzzer in fuzz_filters:
            if fuzz_filter(context):
                steps = fuzzer(steps, context)

        return steps

    return _filter_context


def filter_steps(fuzz_filter=choose_identity, fuzzer=identity):
    """
    A composite fuzzer that applies the supplied fuzzer to a list of steps produced by applying the specified filter
    to the target sequence of steps.
    :param fuzz_filter: a pointer to a function that returns a list of step indices, referencing the target steps to be
     fuzzed.  By default, an identity filter is applied, returning a list containing an index for each step in the
     target steps.
    :param fuzzer: the fuzzer to apply to the filtered steps.
    """
    def _filter_steps(steps, context):
        regions = fuzz_filter(steps)

        for region in regions:
            start = region[0]
            end = region[1]

            filtered_steps = steps[start:end]
            steps[start:end] = fuzzer(filtered_steps, context)
        return steps

    return _filter_steps


def in_sequence(sequence=()):
    """
    A composite fuzz operator that applies the supplied list of fuzz operators in sequence.
    :param sequence: the sequence of fuzz operators to apply.
    :return : a fuzz operator that applies each of the supplied fuzz operators in sequence.
    """

    def _in_sequence(steps, context):
        for fuzzer in sequence:
            steps = fuzzer(steps, context)

        return steps

    return _in_sequence


def choose_from(distribution=(1.0, lambda x: x)):
    """
    A composite fuzz operator that selects a fuzz operator from the supplied probability distribution.
    :param distribution: the probability distribution from which to select a fuzz operator, represented as a sequence of
    (scalar weight, fuzzing operator) tuples.
    :returns : a fuzz operator selected at random from the supplied probability distribution.
    """

    def _choose_from(steps, context):
        total_weight = sum(map(lambda t: t[0], distribution))

        p = pydysofu_random.uniform(0.0, total_weight)

        up_to = 0.0
        for weight, fuzzer in distribution:
            up_to += weight
            if up_to >= p:
                return fuzzer(steps, context)

    return _choose_from


def on_condition_that(condition, fuzzer):
    """
    A composite fuzzer that applies the supplied fuzzer if the specified condition holds.
    :param  condition:  Can either be a boolean value or a 0-ary function that returns a boolean value.
    :param fuzzer: the fuzz operator to apply if the condition holds.
    :returns: a fuzz operator that applies the underlying fuzz operator if the specified condition is satisfied.
    """

    def _on_condition_that(steps, context):
        if hasattr(condition, '__call__'):
            if condition():
                return fuzzer(steps, context)
            else:
                return steps
        elif condition:
            return fuzzer(steps, context)
        else:
            return steps

    return _on_condition_that


def recurse_into_nested_steps(
        fuzzer=identity,
        target_structures={ast.For, ast.TryExcept, ast.While, ast.If},
        min_depth=0,
        max_depth=2 ** 32):
    """
    A composite fuzzer that applies the supplied fuzzer recursively to bodies of control statements (For, While,
    TryExcept and If).  Recursion is applied at the head, i.e. the fuzzer supplied is applied to the parent block last.
    """

    def _recurse_into_nested_steps(steps, context, depth=0):
        if depth <= max_depth:
            for step in steps:
                if type(step) in {ast.For, ast.While} & target_structures:
                    step.body = _recurse_into_nested_steps(step.body, context, depth + 1)
                elif type(step) in {ast.If} & target_structures:
                    step.body = _recurse_into_nested_steps(step.body, context, depth + 1)
                    step.orelse = _recurse_into_nested_steps(step.orelse, context, depth + 1)
                elif type(step) in {ast.TryExcept} & target_structures:
                    step.body = _recurse_into_nested_steps(step.body, context, depth + 1)
                    for handler in step.handlers:
                        _recurse_into_nested_steps(handler.body, context, depth + 1)
        if depth >= min_depth:
            return fuzzer(steps, context)
        else:
            return steps

    return _recurse_into_nested_steps


# Atomic Fuzzers

def replace_condition_with(condition=False):
    """
    An atomic fuzzer that replaces conditions with the supplied condition.
    :param condition: The supplied condition that will be converted into a Python AST boolean expression. The condition
    can be supplied as a:

      * a lambda expression, *provided that* the expression is defined in a single line of code and is enclosed in
        brackets, for example (lambda: False)
      * a function reference
      * string boolean expression, such as '1==2'

    in order of preferred use.

    """

    def build_replacement(step):

        if type(condition) is str:
            parsed_ast = ast.parse('if %s: pass\nelse: False' % condition)
            return parsed_ast.body[0].test

        elif hasattr(condition, '__call__'):

            if hasattr(condition, 'func_name'):

                if condition.func_name == '<lambda>':

                    containing_string = inspect.getsource(condition).strip()
                    func_ast = find_lambda_ast(containing_string, condition).value

                else:
                    func_ast = ast.Name(
                        id=condition.func_name,
                        lineno=step.lineno,
                        col_offset=step.col_offset,
                        ctx=ast.Load()
                    )

            else:
                # TODO be able to call an object.
                func_ast = ast.Name(
                    id='call',
                    lineno=step.lineno,
                    col_offset=step.col_offset,
                    ctx=ast.Load()
                )

            return ast.Call(func=func_ast, col_offset=step.col_offset, lineno=step.lineno, args=list(), keywords=list())

        elif type(condition) is bool:
            return _ast.Name(
                id=str(condition),
                lineno=step.lineno,
                col_offset=step.col_offset,
                ctx=ast.Load()
            )

    @log_invocation
    def _replace_condition(steps, context):

        for step in steps:
            if type(step) is If or type(step) is While:
                step.test = build_replacement(step)
        return steps

    if hasattr(condition, '__call__') and hasattr(condition, 'func_name') and condition.func_name != '<lambda>':

        return in_sequence([
            insert_steps(0, "from %s import %s" % (condition.__module__, condition.func_name)),
            _replace_condition,
        ])

    else:
        return _replace_condition


def replace_for_iterator_with(replacement=()):
    """
    An atomic fuzzer that replaces iterable expressions with the supplied iterable.  The function currently only
    supports lists of numbers and string literals.
    """

    @log_invocation
    def _replace_iterator_with(steps, context):
        for step in steps:
            if type(step) is ast.For:

                if type(replacement) is list:
                    elements = []
                    for i in replacement:
                        if type(i) in {int, long, float, complex}:
                            elements.append(ast.Num(lineno=step.iter.lineno, col_offset=step.iter.col_offset, n=i))
                        elif type(i) is str:
                            elements.append(ast.Str(lineno=step.iter.lineno, col_offset=step.iter.col_offset, s=i))

                    replacement_ast = ast.List(
                        lineno=step.iter.lineno,
                        col_offset=step.iter.col_offset,
                        elts=elements,
                        ctx=step.iter.ctx)

                elif callable(replacement):
                    pass

                step.iter = replacement_ast
        return steps

    return _replace_iterator_with


def replace_steps_with(start=0, end=None, replacement='pass'):
    """
    Replaces one or more lines of code with the specified replacement.  The portion of the code block to be replaced is
    given by the start and end index.
    """

    @log_invocation
    def _replace_steps(steps, context):

        finish = len(steps) if end is None else min(end, len(steps))

        if type(replacement) is str:
            parsed_ast = ast.parse(replacement)
            steps[start:finish] = parsed_ast.body

        elif type(replacement) is ast.Pass:
            steps[start:finish] = [replacement]

        return steps

    return _replace_steps


@log_invocation
def insert_steps(position, insert):
    """
    Inserts one or more lines of code into a target set of steps.
    :param position: The index into the target block of code to insert the lines.
    :param insert: The inserted lines of code are represented as a single string.  Lines of code should be separated by
     a \n carriage return.
    """
    def _insert_steps(steps, context):
        fuzzer = replace_steps_with(position, position, insert)
        return fuzzer(steps, context)

    return _insert_steps


def replace_steps_with_pass(steps, context):
    fuzzer = replace_steps_with(replacement=ast.Pass(lineno=steps[0].lineno, col_offset=steps[0].lineno))
    return fuzzer(steps, context)


@log_invocation
def duplicate_steps(steps, context):
    return steps + copy.deepcopy(steps)


@log_invocation
def shuffle_steps(steps, context):
    result = list(steps)
    pydysofu_random.shuffle(result)
    return result


@log_invocation
def swap_if_blocks(steps, context):
    for step in steps:
        if type(step) is If:
            temp = step.body
            step.body = step.orelse
            step.orelse = temp

    return steps


# Utility Fuzzers

def remove_last_steps(n, reapply=False):
    fuzzer = filter_steps(choose_last_steps(n, reapply), replace_steps_with_pass)
    return fuzzer


def remove_last_step(steps, context):
    fuzzer = remove_last_steps(1)
    return fuzzer(steps, context)


def remove_random_step(steps, context):
    fuzzer = filter_steps(choose_random_steps(1), replace_steps_with_pass)
    return fuzzer(steps, context)


def duplicate_last_step(steps, context):
    fuzzer = filter_steps(choose_last_step, duplicate_steps)
    return fuzzer(steps, context)
