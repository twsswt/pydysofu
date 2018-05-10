import unittest
import pydysofu
import ast
import random

def fuzz_inner_move(steps, context):
    # Fuzz only the function we want to.
    if isinstance(steps[0], ast.FunctionDef):

        symbols = steps[0].body

        def insert_random_step():
            point_to_insert_at = random.choice(range(1, len(steps)-1))
            symbol_to_insert = random.choice(symbols)
            steps.insert(point_to_insert_at, symbol_to_insert)

        def remove_random_step():
            if len(steps)-3 > 0:
                steps.remove(random.choice(steps[1:-1]))

        def randomly_move_step():
            step_original_pos = random.randint(1, len(steps)-1)
            step = steps.pop(step_original_pos)
            steps.insert(step, random.randint(1,len(steps)-1))

        possible_changes = [remove_random_step, insert_random_step, randomly_move_step]

        # Randomly change the steps in any of the ways in possible_changes
        random.choice(possible_changes)()

    # Undo name changes to functions that seem to have been fuzzed, but weren't supposed to be.
    for step_index in range(len(steps)):
        if isinstance(steps[step_index], ast.FunctionDef):
            if steps[step_index].name[-4:] == "_mod":
                steps[step_index].name = steps[step_index].name[:-4]

    return steps

class SantaFeAnt(object):
    '''
    A maze to be solved. At the moment, walls aren't implemented, so the player just moves from top left to bottom right.
    Ordinary play puts the player one square in in each direction, and the size of the grid is 5x5.
    Player just collides with the walls, so if they're at pos y=0 and try to go up, for example, they'll stay at pos y=0.
    '''
    def __init__(self, xlen=5, ylen=5, walls=None, food=list(), total_allowed_moves=0):

        self.pos = {}
        self.reset()
        self.xlen = xlen
        self.ylen = ylen
        self.walls = walls
        self.food = food
        self.path_taken = []
        self.total_allowed_moves = total_allowed_moves

    def move_up(self):
        self.pos['y'] = max(self.pos['y']-1, 0)
        self.record_path()

    def move_down(self):
        self.pos['y'] = min(self.pos['y']+1, self.ylen)
        self.record_path()

    def move_left(self):
        self.pos['x'] = max(self.pos['x']-1, 0)
        self.record_path()

    def move_right(self):
        self.pos['x'] = min(self.pos['x']+1, self.xlen)
        self.record_path()

    def record_path(self):
        self.path_taken.append(self.pos.values())

    def reset(self):
        self.pos = {'x': 0, 'y': 0}
        self.path_taken = []

    def move(self):
        '''
        The standard move for the player in the maze.
        Note that the standard move is a no-op, but also contains movement in the four cardinal directions.
        This means that, when genetically improving, we have a genome that already contains all of our functionality,
        but it needs to be arranged / shuffled properly to make it work as intended. This is what our genetic mutation
        provides.
        :return:  The distance travelled during movement
        '''
        def symbols():
            self.move_down()
            self.move_right()
            self.move_up()
            self.move_left()
        return self.path_taken

    def navigate_trail(self):
        while len(self.path_taken) < self.total_allowed_moves:
            self.move()

    @property
    def food_eaten(self):
        def check_food(acc, pos):
            return acc + 1 if pos in self.food else acc
        return reduce(check_food, self.path_taken, 0)


class AntImprover(pydysofu.GeneticImprover):
    def splice(self, variant_1_steps, variant_2_steps):
        return super(AntImprover, self).splice(variant_1_steps, variant_2_steps)


class TestSantaFeAnt(unittest.TestCase):
    def test_john_muir_trail(self):
        iterations_per_variant = 2
        variants_per_round = 10

        improver = AntImprover(iterations_per_variant=iterations_per_variant,
                               variants_per_round=variants_per_round,
                               success_metric_function=lambda results: sum([len(res) for res in results]) / len(results)) ## Success is the average length of the path of a variant

        number_of_rounds = 10
