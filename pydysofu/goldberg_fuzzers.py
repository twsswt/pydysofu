from asp import encore, prelude
from pydysofu import fuzz_clazz

def target_fuzzing_on_condition_met(trigger, condition_function, fuzzer_to_conditionally_activate):
    '''
    A fuzzer which, if the condition function evaluates to `true`, will trigger another fuzzer to activate by passing it
    a message.
    :param trigger: The function which could trigger the fuzzing based on the condition function
    :param condition_function: A function which takes the result of the trigger and returns a bool.
    :param fuzzer_to_conditionally_activate: The fuzzer which will activate when sent a message.
    :return: A fuzzer, which will act as the identity unless a message is passed to it, in which case it acts as
    fuzzer_to_conditionally_activate.
    '''

    message_channel = list()

    @encore
    def possibly_trigger(attribute, context, result):
        if condition_function(result):
            message_channel.append(True)
        return result

    @prelude
    def possibly_fuzz(steps, context):
        # Do nothing if we don't have to!
        if len(message_channel) is 0:
            return steps

        # There's a value on the message channel, so we want to activate fuzzing.
        # TODO: implement check-lock-check here.
        message_channel.pop()  # One fewer time to fuzz...
        return fuzzer_to_conditionally_activate(steps, context)

    fuzz_clazz(trigger.im_class, {trigger: possibly_trigger})

    return possibly_fuzz