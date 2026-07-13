from vengtoo import Action, EvaluationRequest, Resource, Subject, Vengtoo

client = Vengtoo(api_key="azx_your_api_key_here")

allowed = client.check(
    subject=Subject(id="user-123", type="user"),
    action="read",
    resource=Resource(id="doc-456", type="document"),
)
print("Allowed:", allowed)

resp = client.evaluate(EvaluationRequest(
    subject=Subject(id="user-123", type="user"),
    resource=Resource(id="doc-456", type="document"),
    action=Action(name="read"),
))
reason = resp.context.reason if resp.context else ""
access_path = resp.context.access_path if resp.context else ""
print(f'Decision={resp.decision} Reason="{reason}" Path={access_path}')
