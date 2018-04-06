import unittest
from pydysofu.fuzz_weaver import IncrementalImprover, fuzz_clazz
from pydysofu.core_fuzzers import repeat_random_step


class Maze(object):
    '''
    A maze to be solved. At the moment, walls aren't implemented, so the player just moves from top left to bottom right.
    Ordinary play puts the player one square in in each direction, and the size of the grid is 5x5.
    Player just collides with the walls, so if they're at pos y=0 and try to go up, for example, they'll stay at pos y=0.
    '''
    def __init__(self, xlen = 5, ylen = 5, walls=None):

        self.pos = {}
        self.reset_position()
        self.xlen = xlen
        self.ylen = ylen
        self.walls = walls

    def move_up(self):
        self.pos['y'] = max(self.pos['y']-1, 0)

    def move_down(self):
        self.pos['y'] = min(self.pos['y']+1, self.ylen)

    def move_left(self):
        self.pos['x'] = max(self.pos['x']-1, 0)

    def move_right(self):
        self.pos['x'] = min(self.pos['x']+1, self.xlen)

    def reset_position(self):
        self.pos = {'x': 0, 'y': 0}

    def move(self):
        '''
        The standard move for the player in the maze.
        Note that the standard move is a no-op, but also contains movement in the four cardinal directions.
        This means that, when genetically improving, we have a genome that already contains all of our functionality,
        but it needs to be arranged / shuffled properly to make it work as intended. This is what our genetic mutation
        provides.
        :return:  The distance travelled during movement
        '''
        self.move_down()
        self.move_right()
        self.move_up()
        self.move_left()
        return self.distance_travelled()

    def moves_remaining(self):
        return (self.xlen - self.pos['x']) + (self.ylen - self.pos['y'])

    def distance_travelled(self):
        return self.pos['x'] + self.pos['y']


class IncrementalImproverTest(unittest.TestCase):
    def test_improves_behaviour(self):
        # Some control variables
        round_length = 10
        variants_per_round=6
        number_of_rounds = 8
        def success_metric(x):
            return x

        incremental_improver = IncrementalImprover(round_length=round_length,
                                                   variants_per_round=variants_per_round,
                                                   success_metric_function=success_metric)
        # ==== CONTROL: what happens if we change nothing?

        # Get the initial number of moves remaining after movement.
        maze = Maze()
        maze.reset_position()
        maze.move()

        for i in range(number_of_rounds / 2):
            initial_moves_remaining = maze.moves_remaining()
            best_remaining = maze.moves_remaining()
            for _ in range(2):
                for j in range(variants_per_round * round_length):
                    maze.move()

                    if maze.moves_remaining() < best_remaining:
                        best_remaining = maze.moves_remaining()

                    maze.reset_position()

            # Every two rounds, we should see no improvement - UNLESS we're fuzzing.
            self.assertEqual(initial_moves_remaining, best_remaining)

        # ==== Experiment: applying fuzzing improves our behaviour.
        fuzz_clazz(Maze,
                   {Maze.move: repeat_random_step},
                   advice_aspect=incremental_improver)

        # Get the initial number of moves remaining after movement.
        maze = Maze()
        maze.reset_position()
        maze.move()

        for i in range(number_of_rounds / 2):
            initial_moves_remaining = maze.moves_remaining()
            best_remaining = maze.moves_remaining()
            for _ in range(2):
                for j in range(variants_per_round * round_length):
                    maze.move()

                    if maze.moves_remaining() < best_remaining:
                        best_remaining = maze.moves_remaining()

                    maze.reset_position()

            # Every two rounds, we should see no improvement - UNLESS we're fuzzing.
            self.assertGreater(initial_moves_remaining, best_remaining)

        # After four rounds (240 = 4 * 60) of incremental improvement, we'd expect the solution to be better than the
        # standard moveset, which is a no-op. For this not to happen we'd need to randomly generate 24 (24 = 6 * 4)
        # variants which were all moving in the /wrong/ direction!)
        maze.move()
