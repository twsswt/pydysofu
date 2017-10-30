# PyDySoFu - Python Dynamic Source Fuzzer

A library for fuzzing Python functions at runtime.

## Contributors

* Tom Wallis<br/>
  School of Computing Science, University of Glasgow<br/>
  GitHub ID: probablytom
  [twallisgm@googlemail.com](mailto:twallisgm@googlemail.com)

* Tim Storer<br/>
  School of Computing Science, University of Glasgow<br/>
  GitHub ID: twsswt
  [timothy.storer@glagow.ac.uk](mailto:timothy.storer@glagow.ac.uk)

## Overview

PyDySoFu is a library for performing source code fuzzing of Python programs at runtime. Fuzzing operations are
implemented in an extensible library of fuzzers.  The fuzzers can be applied to functions in in two ways:

 * By constructing an Aspect Oriented Programming like advice dictionary, mapping function pointers to fuzzers
 (recommended).
 * By decorating fuzzable operations with an <code>@fuzz</code> decorator, parameterised with the desired fuzzer.

The AOP approach is preferred because this separates concerns between the implementation of reference functions and the
specification of fuzzers, allowing many different fuzzings of the same program to be constructed.

Each fuzzing operator is a function that accepts the body of a work flow function (as a list of statements) and returns
a fuzzed list of statements.

## Applications

PyDySoFu was originally developed as a fuzzing tool to simulate contingent behaviour in socio-technical systems.
However, there are a number of other possible applications:

 * Simulating Byzantine disruption in distributed system testing.
 * Simulations of complex behaviour in distributed systems.
 * Fallible behaviour in human like computing.
 * Modelling physical systems that are not amenable to stochastic analysis due to emergent complexity. 

## Available Fuzzers

The core library includes both atomic and composite fuzzers for building more complex behaviours:

 * Identity
 * Applying a fuzzer to a subset of function body steps using a filter.  Filters provided include:
  * Identity
  * Random selection
   * n last steps
   * Excluding control structures
   * Inverting a selection
 * Removing steps
 * Replacing steps
 * Duplicating steps
 * Inserting extra steps
 * Shuffling steps
 * Applying a sequence of fuzz operators
 * Choosing a random fuzz operator to apply from a probability distribution.
 * Applying a fuzz operator conditionally.
 * Replacing the iterable of a foreach loop
 * Replacing a condition expression
 * Recursing into composite steps
 * Swapping if blocks

A number of demonstrator fuzzers are also provided that combine the core fuzzers described above:

* Remove last step(s)
* Duplicate last step
* Remove random step

## Tutorials and Examples

 * There is a Jupyter Notebook tutorial available [./tutorial.ipynb](./tutorial.ipynb).
