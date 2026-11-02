"""Assignment 3 Core Engine package.

Pipeline modules:

* ``rule_loader`` - 4.1 load ``.rules`` files into candidates,
* ``rule_parser`` - 4.2 parse/validate into typed InternalRule objects,
* ``rule_repository`` - 4.3 store valid rules and index candidates,
* ``matching`` - 4.4 header/flow/content/flags/dsize matching,
* ``evaluation`` - 4.5 evaluate every candidate and collect matches,
* ``detection`` - 4.6 build structured Detection Events.

Import the submodule you need, for example::

    from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
    from core_engine.rule_parser import RuleParserValidator
    from core_engine.rule_repository import RuleRepository
"""
