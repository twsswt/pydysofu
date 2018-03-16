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

A convenient formulation of a workflow model of a system is to design it as an object-oriented program, where each class
represents a given agent's role. Writing models as programs lens benefits such as easy analytics and behaviour
inspection, but these features cause simulation code to become bloated and more difficult to maintain. Moreover,
complicated model features unrelated to the expected behaviour of the model --- such as varying, contingent behaviours
of unreliable agents --- can severely complicate a model.

Similar problems are solved in software engineering through the use of aspect-orientation [elrad2001aspect], allowing a
developer to seperate the concerns of ancillary program details such as logging and analytics from the intended
behaviour of the relevant code. To this end, we present PyDySoFu, an aspect framework designed to abstract ancillary
details of simulation code from the simulation's indended behaviour. In particular, PyDySoFu is capable of altering
simulation behaviour for modelling things such as varying, contingent behaviour in a simulation of socio-technical
systems, allowing for a developer to separately model an agent's intended behaviour and the "mistakes" they can make. An
example of this is available in the Fuzzi-Moss aspect library using this framework [fuzzimoss_repo].

We envisage aspect-oriented modelling allowing for cleaner models with more easily integrated features. In addition,
where the aspects introduce changes to the model --- such as varying, behaviour --- PyDySoFu allows one to construct
experiments with vcastly different model components *without re-engineering effort*. Evidently, this has applications in
areas such as:

* Human-Centered security modelling
* Safety Critical Systems modelling
* Verifying system architectures prior to construction/deployment
