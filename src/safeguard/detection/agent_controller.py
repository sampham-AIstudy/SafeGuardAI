"""Model-directed orchestration behind the common ControllerSpec boundary."""

from safeguard.detection.execution_host import ControllerReply, ControllerSpec, ExecutionError
from safeguard.detection.model_access import ModelAccess
from safeguard.detection.model_contract import encoded
from safeguard.detection.tools.evidence import PartReference


class AgentController:
    def __init__(self, *, model: ModelAccess, name="agent-controller", version="1.0"):
        if type(model) is not ModelAccess:
            raise ValueError("invalid_agent_model")
        self.model = model
        self.spec = ControllerSpec(name, version, self.execute)

    async def execute(self, invocation, broker):
        conversation = self.model.conversation(invocation)
        try:
            while True:
                reply = await conversation.next(broker)
                output = reply["output"]
                kind = output["kind"]
                if kind == "tool_requests":
                    await conversation.run_tools(broker)
                elif kind == "structured_result":
                    refs = {name: tuple(PartReference(**ref) for ref in output[name])
                            for name in ("supporting", "counter", "unresolved")}
                    return ControllerReply(encoded(output["payload"]), **refs)
                elif kind == "no_result":
                    return ControllerReply(None, unavailable_code=output["reason"],
                        unresolved=tuple(PartReference(**ref) for ref in output["unresolved"]))
                elif kind == "refusal":
                    return ControllerReply(None, unavailable_code="incomplete")
                else:
                    # The outer envelope retains its existing coarse strategy_failed code.
                    raise ExecutionError("model_" + output["code"])
        finally:
            conversation.close()
