"""
@author probablytom
@author twsswt
"""

import unittest

from mock import Mock

import pydysofu as fm
from pydysofu.core_fuzzers import *

fm.fuzz.enable_fuzzings = True


def bool_func():
    return False


class ExampleWorkflow(object):

    def __init__(self, environment):
        self.environment = environment

    @fm.fuzz(identity)
    def mangled_function_identity(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(remove_last_step)
    def mangled_function_remove_last_step(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(duplicate_last_step)
    def mangled_function_duplicate_last_step(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(remove_random_step)
    def mangled_function_remove_random_step(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(in_sequence([remove_random_step, remove_random_step, remove_random_step]))
    def mangled_function_replace_all_steps_with_pass_in_random_sequence(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(shuffle_steps)
    def mangled_function_shuffle_steps(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(choose_from([(0.5, identity), (0.5, remove_last_step)]))
    def mangled_function_choose_from(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(in_sequence([remove_last_step, remove_last_step]))
    def mangled_function_in_sequence(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(in_sequence([remove_last_step, remove_last_step, remove_last_step]))
    def mangled_function_remove_all_steps(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(on_condition_that(True, remove_last_step))
    def mangled_function_on_condition_that(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(on_condition_that(bool_func, remove_last_step))
    def mangled_function_on_condition_that_with_function(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    @fm.fuzz(swap_if_blocks)
    def mangled_function_swap_if_blocks(self):
        if True:
            self.environment.append(1)
        else:
            self.environment.append(2)

    @fm.fuzz(replace_condition_with('1 is 2'))
    def mangled_function_replace_condition(self):
        if 1 is 1:
            self.environment.append(1)
        else:
            self.environment.append(2)

    @fm.fuzz(replace_condition_with(bool_func))
    def mangled_function_replace_condition_with_function(self):
        """
        TODO Ideally, it would be nice to use this fuzzer with a lambda expression.  Unfortunately, there is a bug in
        the BlockFinder class, inspect.py due to an assumption that lambda expressions are always defined on one line.
        This assumption doesn't hold, if the lambda is nested within a decorator for the function we actually want the
         lines of code for.
        """
        if 1 is 1:
            self.environment.append(1)
        else:
            self.environment.append(2)

    @fm.fuzz(replace_condition_with(False))
    def mangled_function_replace_condition_with_literal(self):
        if 1 is 1:
            self.environment.append(1)
        else:
            self.environment.append(2)

    @fm.fuzz(remove_last_step)
    def make_nested_fuzzing_call(self):
        self.nested_method_call()
        self.environment.append(3)
        self.environment.append(4)

    @fm.fuzz(remove_last_step)
    def nested_method_call(self):
        self.environment.append(1)
        self.environment.append(2)

    @fm.fuzz(replace_for_iterator_with([3, 2, 1]))
    def mangled_function_replace_iterator(self):
        for i in [1, 2, 3, 4, ]:
            self.environment.append(i)

    @fm.fuzz(recurse_into_nested_steps(remove_last_step, target_structures={ast.For, ast.TryExcept}))
    def manged_function_with_nested_for_and_try(self):
        for i in range(0, 3):
            try:
                self.environment.append(i)
                if i == 2:
                    raise Exception()
                self.environment.append("TO BE REMOVED")
            except Exception:
                self.environment.append(7)
                self.environment.append(9)
            self.environment.append("TO BE REMOVED")
        self.environment.append("TO BE REMOVED")

    @fm.fuzz(filter_steps(exclude_control_structures({ast.For}), remove_last_step))
    def mangled_function_excluding_control_structures(self):
        if True:
            self.environment.append(1)

        for i in range(1, 3):
            self.environment.append(i)

    @fm.fuzz(filter_steps(invert(choose_last_step), replace_steps_with_pass))
    def mangled_function_invert_filter(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)
        return 4

    @fm.fuzz(filter_steps(invert(invert(choose_last_step)), replace_steps_with_pass))
    def mangled_function_invert_invert_filter(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)
        return 4


class FuzziMossDecoratorTest(unittest.TestCase):

    def setUp(self):
        self.environment = list()
        self.target = ExampleWorkflow(self.environment)

    def test_identity(self):
        self.target.mangled_function_identity()
        self.assertEquals([1, 2, 3], self.environment)

    def test_remove_last_step(self):
        self.target.mangled_function_remove_last_step()
        self.assertEqual([1, 2], self.environment)

    def test_remove_last_step_twice(self):
        self.target.mangled_function_remove_last_step()
        self.target.mangled_function_remove_last_step()
        self.assertEqual([1, 2, 1, 2], self.environment)

    def test_duplicate_last_step(self):
        self.target.mangled_function_duplicate_last_step()
        self.assertEqual([1, 2, 3, 3], self.environment)

    def test_remove__random_step(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[1]])

        self.target.mangled_function_remove_random_step()
        self.assertEqual([1, 3], self.environment)

    def test_remove__random_step_twice(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[1], [2]])

        self.target.mangled_function_remove_random_step()
        self.target.mangled_function_remove_random_step()
        self.assertEqual([1, 3, 1, 2], self.environment)

    def test_replace_all_steps_with_pass_in_random_sequence(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[0], [1], [2]])

        self.target.mangled_function_replace_all_steps_with_pass_in_random_sequence()
        self.assertEqual([], self.environment)

    def test_remove_all_steps(self):
        self.target.mangled_function_remove_all_steps()
        self.assertEqual([], self.environment)

    def test_shuffle_steps(self):
        def mock_random_shuffle(iterable):
            result = list()
            result.append(iterable[2])
            result.append(iterable[0])
            result.append(iterable[1])
            return result

        fm.pydysofu_random.shuffle = Mock(side_effect=mock_random_shuffle)

        self.target.mangled_function_shuffle_steps()
        self.assertEqual([3, 1, 2], self.environment)

    def test_swap_if_blocks(self):
        self.target.mangled_function_swap_if_blocks()
        self.assertEqual([2], self.environment)

    def test_choose_from(self):
        fm.pydysofu_random.uniform = Mock(side_effect=[0.75, 0.75])

        self.target.mangled_function_choose_from()
        self.target.mangled_function_choose_from()
        self.assertEqual([1, 2, 1, 2], self.environment)

    def test_in_sequence(self):
        self.target.mangled_function_in_sequence()
        self.assertEqual([1], self.environment)

    def test_on_condition_that(self):
        self.target.mangled_function_on_condition_that()
        self.assertEqual([1, 2], self.environment)

    def test_on_condition_that_with_function(self):
        self.target.mangled_function_on_condition_that_with_function()
        self.assertEqual([1, 2, 3], self.environment)

    def test_replace_condition(self):
        self.target.mangled_function_replace_condition()
        self.assertEquals([2], self.environment)

    def test_replace_condition_with_function(self):
        self.target.mangled_function_replace_condition_with_function()
        self.assertEquals([2], self.environment)

    def test_replace_condition_with_literal(self):
        self.target.mangled_function_replace_condition_with_literal()
        self.assertEquals([2], self.environment)

    def test_make_nested_fuzzing_call(self):
        self.target.make_nested_fuzzing_call()
        self.assertEquals([1, 3], self.environment)

    def test_replace_iterator(self):
        self.target.mangled_function_replace_iterator()
        self.assertEquals([3, 2, 1], self.environment)

    def test_apply_fuzzer_to_nested_statements(self):
        self.target.manged_function_with_nested_for_and_try()
        self.assertEquals([0, 1, 2, 7], self.environment)
        pass

    def test_mangled_function_excluding_control_structures(self):
        self.target.mangled_function_excluding_control_structures()
        self.assertEquals([1, 2], self.environment)

    def test_mangled_function_invert_filter(self):
        result = self.target.mangled_function_invert_filter()
        self.assertEquals(4, result)
        self.assertEquals(self.environment, [])

    def test_mangled_function_invert_invert_filter(self):
        result = self.target.mangled_function_invert_invert_filter()
        self.assertEquals(None, result)
        self.assertEquals(self.environment, [1, 2, 3])


if __name__ == '__main__':
    unittest.main()
