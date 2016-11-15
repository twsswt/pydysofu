"""
Utility routines for extracting lambda expressions from source files.
@twsswt
"""

import ast


def find_candidate_object(offset, source_line):
    start = source_line.index('lambda', offset)-1
    end = start + 7

    while end <= len(source_line):
        try:
            candidate_source = source_line[start:end]
            return compile(candidate_source, filename='blank', mode='exec').co_consts[0], candidate_source, end
        except SyntaxError:
            end += 1


def find_lambda_ast(source_line, lambda_object):
    """
    Searches for the source code representation of the supplied lambda object within the line of code. Note that the
    source line does not have to be a valid Python statement or expression, but *the search assumes that the lambda
    expression is delimited by brackets*. Compiled byte codes and name declarations from the supplied lambda_object
    are compared against potential candidates, since a source line may contain several lambda functions.

    :param source_line: the line of code to search.
    :param lambda_object: the compiled representation of the lambda expression.
    :return : An AST representation of the lambda expression.
    """
    offset = 0
    while True:
        candidate_object, candidate_source, offset = find_candidate_object(offset, source_line)

        if candidate_object.co_code == lambda_object.func_code.co_code:
            if candidate_object.co_names == lambda_object.func_code.co_names:
                return ast.parse(candidate_source).body[0]
