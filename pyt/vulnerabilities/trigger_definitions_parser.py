import json
from collections import namedtuple


Definitions = namedtuple(
    'Definitions',
    (
        'sources',
        'sinks'
    )
)

Source = namedtuple('Source', ('trigger_word'))


class Sink:
    def __init__(
        self, trigger, *,
        args_that_propagate_taint=None, kwargs_that_propagate_taint=None,
        args_that_dont_propagate_taint=None, kwargs_that_dont_propagate_taint=None,
        sanitisers=None
    ):
        self._trigger = trigger
        self.sanitisers = sanitisers or []
        if args_that_propagate_taint:
            if args_that_dont_propagate_taint:
                raise ValueError("Sink definition specifies both an args whitelist and blacklist")
            self._arg_list = args_that_propagate_taint
            self._arg_list_propagates = True
        else:
            self._arg_list_propagates = False
            self._arg_list = args_that_dont_propagate_taint or []
        if kwargs_that_propagate_taint:
            if kwargs_that_dont_propagate_taint:
                raise ValueError("Sink definition specifies both a kwargs whitelist and blacklist")
            self._kwarg_list = kwargs_that_propagate_taint
            self._kwarg_list_propagates = True
        else:
            self._kwarg_list_propagates = False
            self._kwarg_list = kwargs_that_dont_propagate_taint or []

    @property
    def call(self):
        if self._trigger[-1] == '(':
            return self._trigger[:-1]
        return None

    @property
    def trigger_word(self):
        return self._trigger

    @classmethod
    def from_json(cls, key, data):
        return cls(trigger=key, **data)


def parse(trigger_word_file):
    """Parse the file for source and sink definitions.

    Returns:
       A definitions tuple with sources and sinks.
    """
    with open(trigger_word_file) as fd:
        triggers_dict = json.load(fd)
    sources = [Source(s) for s in triggers_dict['sources']]
    sinks = [
        Sink.from_json(trigger, data)
        for trigger, data in triggers_dict['sinks'].items()
    ]
    return Definitions(sources, sinks)
