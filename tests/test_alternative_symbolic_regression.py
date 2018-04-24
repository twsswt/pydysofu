from pydysofu import fuzz_clazz, GeneticImprover
from math import sin, cos, exp, log
from copy import deepcopy
import unittest
import random
import ast

def fuzz_inner_regression(steps, context):
    # Fuzz only the function we want to.
    if isinstance(steps[0], ast.FunctionDef):

        symbols = steps[0].body

        def insert_random_step():
            point_to_insert_at = random.choice(range(1, len(steps)-1))
            symbol_to_insert = random.choice(symbols)
            steps.insert(point_to_insert_at, symbol_to_insert)

        def remove_random_step():
            if len(steps)-3 > 0:
                steps.remove(random.choice(steps[1:-2]))

        possible_changes = [remove_random_step, insert_random_step]

        # Randomly change the steps in any of the ways in possible_changes
        random.choice(possible_changes)()

    # Undo name changes to functions that seem to have been fuzzed, but weren't supposed to be.
    for step_index in range(len(steps)):
        if isinstance(steps[step_index], ast.FunctionDef):
            if steps[step_index].name[-4:] == "_mod":
                steps[step_index].name = steps[step_index].name[:-4]

    return steps


def distance_from(func_to_fit):
    def distance(results):
        def distance_at_point(acc, res_tuple):
            return acc + abs(func_to_fit(res_tuple[0]) - res_tuple[1])
        return reduce(distance_at_point, results.items(), 0)
    return distance


class SymbolicRegression(object):

    def __init__(self, datapoints):
        self.results = dict()
        self.stacks = dict()
        self.datapoints = datapoints

    def perform_regression(self):
        self.results, self.stacks = dict(), dict()

        def perform_regression_against_datapoint(datapoint):
            def symbols():
                self.add(datapoint)
                self.sub(datapoint)
                self.mul(datapoint)
                self.div(datapoint)
                self.sin(datapoint)
                self.cos(datapoint)
                self.exp(datapoint)
                self.log(datapoint)
            self.results[datapoint] = self.pop_next_in_stack(datapoint)
            self.stacks[datapoint] = []

        for point in self.datapoints:
            perform_regression_against_datapoint(point)

        return self.results

    def pop_next_in_stack(self, datapoint):
        stack = self.stacks.get(datapoint, [])
        if len(stack) == 0:
            stack.append(datapoint)
        n = stack.pop()
        self.stacks[datapoint] = stack
        return n

    def add_to_stack(self, datapoint, val):
        stack = self.stacks.get(datapoint, [])
        stack.append(val)
        self.stacks[datapoint] = stack

    def add(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        b = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, a+b)

    def sub(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        b = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, a-b)

    def mul(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        b = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, a*b)

    def div(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        b = self.pop_next_in_stack(datapoint)
        def checked_div(m, n):
            if n == 0 or m == 0:
                return 0
            return m/n
        self.add_to_stack(datapoint, checked_div(a, b))

    def sin(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, sin(a))

    def cos(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, cos(a))

    def exp(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        self.add_to_stack(datapoint, exp(a))

    def log(self, datapoint):
        a = self.pop_next_in_stack(datapoint)
        def checked_log(n):
            n = abs(n)
            if n is 0:
                return 0
            if n > 1:
                return log(1)
            return log(n)

        self.add_to_stack(datapoint, checked_log(a))


class RegressionImprover(GeneticImprover):
    def splice(self, variant_1_steps, variant_2_steps):
        variant_1_symbols = variant_1_steps[1:-2]
        variant_2_symbols = variant_2_steps[1:-2]
        new_symbols = super(RegressionImprover, self).splice(variant_1_symbols, variant_2_symbols)

        new_steps = deepcopy(variant_1_steps)

        new_steps[1:-2] = new_symbols

        return new_steps

    def sort_key(self, x):
        return x[1]



class TestStateBasedSymbolicRegression(unittest.TestCase):
    def run_regression_against(self, func_to_fit):
        for seed in range(0, 5000, 250):
            random.seed(seed)

            variants_per_round = 3
            iterations_per_variant = 1
            number_of_rounds = 4
            number_of_points = 20

            datapoints = [random.random()*random.choice([-1, 1]) for _ in range(number_of_points)]

            improver = RegressionImprover(variants_per_round=variants_per_round,
                                          iterations_per_variant=iterations_per_variant,
                                          success_metric_function=distance_from(func_to_fit)
                                          )

            fuzz_clazz(SymbolicRegression,
                       fuzzing_advice={SymbolicRegression.perform_regression: fuzz_inner_regression},
                       advice_aspect=improver)

            regresser = SymbolicRegression(datapoints)

            for i in range(number_of_rounds):
                for j in range(variants_per_round):
                    regresser.perform_regression()

            for i in range(number_of_rounds-1):
                average_distance_from_func = improver.variants_ordered_by_success[i+1][0][1]
                previous_distance_from_func = improver.variants_ordered_by_success[i][0][1]
                self.assertLessEqual(average_distance_from_func, previous_distance_from_func)

    def test_solves_symbolic_regression_koza_1(self):

        self.run_regression_against(lambda x: x ** 4 + x ** 3 + x ** 2 + x)

    def test_solves_symbolic_regression_koza_2(self):

        self.run_regression_against(lambda x: x ** 5 - x ** 3 + x)

    def test_solves_symbolic_regression_koza_3(self):

        self.run_regression_against(lambda x: x ** 6 - x ** 4 + x ** 2)
