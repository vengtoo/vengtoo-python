from authzx import AuthzX, Subject, Resource, Action, AuthorizeRequest

client = AuthzX(api_key="azx_your_api_key_here")

allowed = client.check(
    subject=Subject(id="user-123"),
    action="read",
    resource=Resource(id="doc-456"),
)
print("Allowed:", allowed)

resp = client.authorize(AuthorizeRequest(
    subject=Subject(id="user-123"),
    resource=Resource(id="doc-456"),
    action=Action(name="read"),
))
reason = resp.context.reason if resp.context else ""
access_path = resp.context.access_path if resp.context else ""
print(f'Decision={resp.decision} Reason="{reason}" Path={access_path}')
