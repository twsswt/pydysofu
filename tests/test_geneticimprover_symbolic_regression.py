from pydysofu import IncrementalImprover, fuzz_clazz, GeneticImprover
import random
import unittest
from math import sin, cos, exp, log
import inspect
import copy

seed = 0


def mutate_for_symbolic_regression(steps, context):
    # Catch the recursive application to the inner function definition
    if len(steps) != 3:
        return steps

    # Fix recorsive function definition name if we've already "fuzzed" it
    if "_mod" == steps[1].body[8].name[-4:]:
        steps[1].body[8].name = steps[1].body[8].name[:-4]

    # The actual incremental improvement, up to 10 times.
    for i in range(random.randint(0, 10)):
        steps[1].body[9].value.elts.append(random.choice(steps[1].body[:7]).value)

    return steps


def get_arity(func):
    return len(inspect.getargspec(func)[0])


class SymbolicRegresser(object):
    def __init__(self):
        random.seed(seed)
        self.points_for_regression = [random.random()*random.choice([1, -1]) for _ in range(20)]

    def improving_func(self):
        results = []
        for i in self.points_for_regression:

            # begin symbols
            lambda x, y: x + y
            lambda x, y: x * y
            lambda x, y: x - y
            lambda x, y: 1 if y == 0 else (x / y)
            lambda x, y: 0 if y == 0 else log(abs(x))
            lambda x: sin(x)
            lambda x: cos(x)
            lambda x: exp(x)
            # end symbols

            def run_next_func(acc, func):

                if get_arity(func) == 1:
                    return func(acc)
                elif get_arity(func) == 2:
                    return func(acc, i)
                else:
                    raise Exception("Bad arity")

            function_sequence = []
            res = reduce(run_next_func,
                         function_sequence,
                         i)
            results.append((i, res))

        return results


def fitness_generator(function_to_fit):
    def success_metric(result):
        def distance_from_expected(acc, res):
            return acc + abs(function_to_fit(res[0])-res[1])
        return reduce(distance_from_expected, result, 0)
    return success_metric


class GeneticProgrammingSymbolicRegresser(GeneticImprover):
    def splice(self, variant_1_tree, variant_2_tree):
        function_list_1 = variant_1_tree.body[0].body[1].body[9].value.elts
        function_list_2 = variant_2_tree.body[0].body[1].body[9].value.elts
        splice_point = random.randint(0, min(len(function_list_1), len(function_list_2)))
        new_function_list = function_list_1[:splice_point] + function_list_2[splice_point:]

        new_tree = copy.deepcopy(variant_1_tree)
        new_tree.body[0].body[1].body[9].value.elts = new_function_list

        return new_tree


class TestGeneticProgramming(unittest.TestCase):
    '''
    Tests whether we can really implement a GP problem by solving symbolic regression.
    (According to Essentials of Metaheuristics pg.220, the standard GP problem to solve.)
    (What we're implementing here is exactly the problem they lay out.)
    '''

    def run_regression_against(self, func_to_fit):
        random.seed(0)

        variants_per_round = 10
        iterations_per_variant = 1
        number_of_rounds = 4
        fitness = fitness_generator(func_to_fit)

        improver = GeneticProgrammingSymbolicRegresser(variants_per_round=variants_per_round,
                                                       iterations_per_variant=iterations_per_variant,
                                                       success_metric_function=fitness
                                                       )

        fuzz_clazz(SymbolicRegresser,
                   fuzzing_advice={SymbolicRegresser.improving_func: mutate_for_symbolic_regression},
                   advice_aspect=improver)

        improving_func = SymbolicRegresser().improving_func

        fitnesses = []
        for i in range(number_of_rounds):
            for j in range(variants_per_round):
                improving_func()
            fitnesses.append(improver.best_attribute_in_last_round[1])

        [self.assertLess(fitnesses[i+1], fitnesses[i]) for i in range(number_of_rounds-1)]  # TODO: Actually run the regression, and show that we get closer as we mutate!

    def test_solves_symbolic_regression_koza_1(self):

        self.run_regression_against(lambda x: x ** 4 + x ** 3 + x ** 2 + x)

    def test_solves_symbolic_regression_koza_2(self):

        self.run_regression_against(lambda x: x ** 5 - x ** 3 + x)

    def test_solves_symbolic_regression_koza_3(self):

        self.run_regression_against(lambda x: x ** 6 - x ** 4 + x ** 2)

