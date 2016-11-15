class ExampleWorkflow(object):
    """
    An example workflow class containing functions that can be fuzzed for unit testing.
    """

    def __init__(self, environment):
        self.environment = environment

    def method_for_fuzzing(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)

    def method_for_fuzzing_that_returns_4(self):
        self.environment.append(1)
        self.environment.append(2)
        self.environment.append(3)
        return 4

    def method_containing_if(self):
        if True:
            self.environment.append(1)
        else:
            self.environment.append(2)

    def make_nested_fuzzing_call(self):
        self.nested_method_call()
        self.environment.append(3)
        self.environment.append(4)

    def nested_method_call(self):
        self.environment.append(1)
        self.environment.append(2)

    def method_containing_iterator(self):
        for i in [1, 2, 3, 4]:
            self.environment.append(i)

    def method_containing_for_and_nested_try(self):
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

    def method_containing_if_followed_by_for(self):
        if True:
            self.environment.append(1)

        for i in range(1, 3):
            self.environment.append(i)

    @staticmethod
    def example_class_method():
        return 1
