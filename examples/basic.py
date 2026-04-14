from authzx import AuthzX, Subject, Resource, AuthorizeRequest

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
    action="read",
))
print(f'Allowed={resp.allowed} Reason="{resp.reason}" Path={resp.access_path}')
