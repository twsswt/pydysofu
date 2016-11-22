import unittest

from mock import Mock

import pydysofu as fm

from pydysofu.core_fuzzers import *

from example_workflow import ExampleWorkflow

from random import Random


class FuzziMossWeaverTest(unittest.TestCase):

    def setUp(self):
        self.environment = list()
        self.target = ExampleWorkflow(self.environment)

    def test_identity(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: identity
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEquals([1, 2, 3], self.environment)

    def test_remove_last_step(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: remove_last_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1, 2], self.environment)

    def test_remove_last_step_twice(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: remove_last_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.target.method_for_fuzzing()
        self.assertEqual([1, 2, 1, 2], self.environment)

    def test_duplicate_last_step(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: duplicate_last_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1, 2, 3, 3], self.environment)

    def test_remove_random_step(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[1]])

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: remove_random_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1, 3], self.environment)

    def test_remove__random_step_twice(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[1], [2]])

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: remove_random_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.target.method_for_fuzzing()
        self.assertEqual([1, 3, 1, 2], self.environment)

    def test_replace_all_steps_with_pass_in_random_sequence(self):
        fm.pydysofu_random.sample = Mock(side_effect=[[0], [1], [2]])

        test_advice = {
            ExampleWorkflow.method_for_fuzzing:
                in_sequence([remove_random_step, remove_random_step, remove_random_step])
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([], self.environment)

    def test_remove_all_steps(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: in_sequence([remove_last_step, remove_last_step, remove_last_step])
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([], self.environment)

    def test_shuffle_steps(self):
        def mock_random_shuffle(iterable):
            result = list()
            result.append(iterable[2])
            result.append(iterable[0])
            result.append(iterable[1])
            return result

        fm.pydysofu_random.shuffle = Mock(side_effect=mock_random_shuffle)

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: shuffle_steps
        }

        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([3, 1, 2], self.environment)

    def test_swap_if_blocks(self):

        test_advice = {
            ExampleWorkflow.method_containing_if: swap_if_blocks
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_if()
        self.assertEqual([2], self.environment)

    def test_choose_from(self):
        fm.pydysofu_random.uniform = Mock(side_effect=[0.75, 0.75])

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: choose_from([(0.5, identity), (0.5, remove_last_step)])
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.target.method_for_fuzzing()
        self.assertEqual([1, 2, 1, 2], self.environment)

    def test_in_sequence(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: in_sequence([remove_last_step, remove_last_step])
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1], self.environment)

    def test_on_condition_that(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: on_condition_that(True, remove_last_step)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1, 2], self.environment)

    def test_on_condition_that_with_function(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: on_condition_that(lambda: False, remove_last_step)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()
        self.assertEqual([1, 2, 3], self.environment)

    def test_replace_condition(self):

        test_advice = {
            ExampleWorkflow.method_containing_if: replace_condition_with('1 is 2')
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_if()
        self.assertEquals([2], self.environment)

    def test_replace_condition_with_function(self):

        test_advice = {
            ExampleWorkflow.method_containing_if: replace_condition_with(lambda: False)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_if()
        self.assertEquals([2], self.environment)

    def test_replace_condition_with_literal(self):

        test_advice = {
            ExampleWorkflow.method_containing_if: replace_condition_with(False)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_if()
        self.assertEquals([2], self.environment)
        pass

    def test_make_nested_fuzzing_call(self):

        test_advice = {
            ExampleWorkflow.make_nested_fuzzing_call: remove_last_step,
            ExampleWorkflow.nested_method_call: remove_last_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.make_nested_fuzzing_call()
        self.assertEquals([1, 3], self.environment)

    def test_replace_iterator(self):

        test_advice = {
            ExampleWorkflow.method_containing_iterator:  replace_for_iterator_with([3, 2, 1])
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_iterator()
        self.assertEquals([3, 2, 1], self.environment)

    def test_apply_fuzzer_to_nested_statements(self):

        test_advice = {
            ExampleWorkflow.method_containing_for_and_nested_try:
                recurse_into_nested_steps(remove_last_step, target_structures={ast.For, ast.TryExcept})
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_for_and_nested_try()
        self.assertEquals([0, 1, 2, 7], self.environment)
        pass

    def test_mangled_function_excluding_control_structures(self):

        test_advice = {
            ExampleWorkflow.method_containing_if_followed_by_for:
                filter_steps(exclude_control_structures({ast.For}), remove_last_step)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_containing_if_followed_by_for()
        self.assertEquals([1, 2], self.environment)

    def test_mangled_function_invert_filter(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing_that_returns_4:
                filter_steps(invert(choose_last_step), replace_steps_with_pass)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        result = self.target.method_for_fuzzing_that_returns_4()
        self.assertEquals(4, result)
        self.assertEquals(self.environment, [])

    def test_mangled_function_invert_invert_filter(self):
        test_advice = {
            ExampleWorkflow.method_for_fuzzing_that_returns_4:
                filter_steps(invert(invert(choose_last_step)), replace_steps_with_pass)
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        result = self.target.method_for_fuzzing_that_returns_4()
        self.assertEquals(None, result)
        self.assertEquals(self.environment, [1, 2, 3])

    def test_fuzzing_class_method(self):
        test_advice = {
            ExampleWorkflow.example_class_method:
                remove_last_step
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        result = self.target.example_class_method()
        self.assertEquals(None, result)

    def test_insert_code(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing: insert_steps(0, 'self.environment.append(4)')
        }
        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()

        self.assertEquals(self.environment, [4, 1, 2, 3])

    def test_fuzz_specific_object(self):

        test_advice = {
            ExampleWorkflow.method_for_fuzzing:
                {lambda o: hasattr(o, 'name') and o.name == 'a workflow': remove_last_step}
        }

        fm.fuzz_clazz(ExampleWorkflow, test_advice)

        self.target.method_for_fuzzing()

        self.assertEquals(self.environment, [1, 2, 3])

        self.target.name = 'a workflow'
        self.target.method_for_fuzzing()

        self.assertEquals(self.environment, [1, 2, 3, 1, 2])


if __name__ == '__main__':
    unittest.main()
