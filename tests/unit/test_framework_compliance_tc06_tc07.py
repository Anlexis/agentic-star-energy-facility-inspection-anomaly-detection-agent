"""TC-06 / TC-07: FunctionNode security gates must not be bypassable.

These framework-compliance tests are required for every template that has one or
more FunctionNode subclasses. They verify the framework's own enforcement: a
domain node may extend the input/output gates only through
_extra_security_gate_input() and _extra_security_gate_output(), never by
overriding the gate methods themselves.
"""

import pytest

from framework.nodes.function_node import FunctionNode
from framework.schemas.trust_level import TrustLevel


class TestFunctionNodeGateFinality:
    """The gate methods are final; overriding one fails at class definition time."""

    def test_tc06_input_gate_override_is_rejected(self):
        """TC-06: overriding the default input gate raises at class definition."""
        with pytest.raises(TypeError):

            class BadInputNode(FunctionNode):
                required_trust_level = TrustLevel.ANONYMOUS

                def _security_gate_input(self, state):  # type: ignore[override]
                    return state

                def execute(self, state):
                    return {}

    def test_tc07_output_gate_override_is_rejected(self):
        """TC-07: overriding the default output gate raises at class definition."""
        with pytest.raises(TypeError):

            class BadOutputNode(FunctionNode):
                required_trust_level = TrustLevel.ANONYMOUS

                def _security_gate_output(self, result):  # type: ignore[override]
                    return result

                def execute(self, state):
                    return {}

    def test_required_trust_level_must_be_declared(self):
        """A node that omits an explicit trust level cannot be defined."""
        with pytest.raises(TypeError):

            class UndeclaredNode(FunctionNode):
                def execute(self, state):
                    return {}
