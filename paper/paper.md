---
title: A tool for dynamically fuzzing agent behaviour in workflow models
tags:
    - systems modelling
    - python
    - agent-based modelling
authors:
    - name: Tim Storer
      affiliation: 1
    - Tom Wallis
      affiliation: 1
affiliantions:
    - name: University of Glasgow
      index: 1
date: CURRENT DATE
bibliography: refs.bib
---

In constructing agent-based models of systems, variation in the simulated behaviour is often a crucial component. Examples might include simulations of security systems where human agents do not always behave predictably, leading to important edge cases which must be identified during he modelling process. However, hard-coding this variance leads to unwieldy models which are cumbersome to develop and maintain — this leaves models either incomplete (without variance) or overly complex (when variance is hard-coded).

PyDySoFu is a Python library which simplifies modelling with variance via aspect-orientation [elrad2001aspect]. Using the workflow modelling library Theatre_ag, PyDySoFu applies variance to behaviours by dynamically fuzzing the workflow. Dynamic fuzzing is the alteration of simulation program code at runtime. This approach has a number of benefits:

* The model becomes a blueprint of expected behaviour, and advice applied to each workflow step serves as an indicator for “mistakes” in the blueprint’s execution. This allows for the separation of the concerns of defining the model and defining its variance.
* The fuzzing is applied using aspects, so that the underlying task description is oblivious to the simulated mutations. This allows many different fuzzing combinations to easily be experimented with [elrad2001aspect], using the separation of concerns to simplify the model's architecture.
* Dynamic fuzzing permits a simple model definition without requiring a DSL, making the development and maintainance of the model simpler, as well as increasing readability by utilising popular general-purpose languages.
